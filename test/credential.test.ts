/**
 * @file What counts as a credential, and what is done with it on the wire.
 *
 * The fixture pins the *answers* for a malformed `Authorization` header. This
 * file pins the two things it cannot see from outside: that a hostile token is
 * transmitted encoded and arrives byte-identical, and that the header parser
 * never invents a credential out of one that is malformed — including what two
 * `Authorization` lines really do on the wire, which is not what this package
 * used to claim.
 *
 * Every case here is a mutation that would otherwise survive: joining the
 * remainder of a split header, accepting an empty token, picking one of two
 * credentials in a folded header, or writing the token into the body raw.
 */

import { createServer, type Server } from "node:http";
import { once } from "node:events";
import { connect, type AddressInfo } from "node:net";

import { createIntrospector } from "../src/center";
import { authorizationLines, bearerFrom, isSafeMethod } from "../src/core";
import { DEFAULT_TIMEOUT_MS, SECRET_HEADER } from "../src/messages";

const SECRET = "credential-suite-secret";

interface Seen {
  readonly rawBody: string;
  readonly contentLength: string | undefined;
  readonly headerNames: readonly string[];
  readonly headerValues: readonly string[];
  readonly url: string;
}

/** A stub that records the exact bytes of the request and answers active. */
const startEchoCenter = async (): Promise<{
  url: string;
  seen: Seen[];
  close: () => Promise<void>;
}> => {
  const seen: Seen[] = [];
  const server: Server = createServer((req, res) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      seen.push({
        rawBody: Buffer.concat(chunks).toString("utf8"),
        contentLength: req.headers["content-length"],
        headerNames: Object.keys(req.headers),
        headerValues: Object.values(req.headers).map((v) => String(v)),
        url: req.url ?? "",
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        '{"active":true,"sub":"user_x","scope":"fleet:control","exp":4102444800,"kind":"operator"}'
      );
    })();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/auth/v1/introspect`,
    seen,
    close: async () => {
      server.closeAllConnections();
      server.close();
      await once(server, "close");
    },
  };
};

describe("a hostile token reaches the center intact and changes nothing else", () => {
  // Every byte here means something to a form body, a URL or a header parser.
  const HOSTILE = [
    ["an ampersand and an equals", "a&b=c"],
    ["a plus, which a form decoder reads as a space", "a+b"],
    ["a percent, which is the escape character itself", "100%pure"],
    ["a CR and an LF, the header-injection bytes", "a\r\nX-Injected: yes\r\n\r\nb"],
    ["all of them at once", "a&b=c+d%e\r\nX-Injected: yes"],
    ["a space", "a b"],
    ["a hash and a question mark", "a?b#c"],
  ] as const;

  it.each(HOSTILE)("%s", async (_name, token) => {
    const center = await startEchoCenter();
    try {
      const answer = await createIntrospector({
        url: center.url,
        secret: SECRET,
      }).introspect(token);

      expect(answer.state).toBe("active");
      expect(center.seen).toHaveLength(1);
      const sent = center.seen[0];
      if (sent === undefined) throw new Error("the center saw no request");

      // Sent encoded: the raw bytes never appear in the body as written.
      const encoded = encodeURIComponent(token);
      expect(sent.rawBody).toBe(`token=${encoded}`);

      // And decoded back, it is byte-identical to what we were handed. A
      // client that skipped encoding would truncate `a&b=c` at the ampersand
      // and hand the center a different token than the caller presented,
      // which reads as an expired session rather than as a bug.
      expect(new URLSearchParams(sent.rawBody).get("token")).toBe(token);

      // Content-Length counts the encoded bytes. A length computed before
      // encoding leaves the center reading a truncated body, or hanging.
      expect(sent.contentLength).toBe(
        String(Buffer.byteLength(`token=${encoded}`, "utf8"))
      );

      // No header was injected, and nothing carrying the token's bytes
      // arrived as a header of its own.
      expect(sent.headerNames).not.toContain("x-injected");
      for (const value of sent.headerValues) {
        expect(value).not.toContain("\r");
        expect(value).not.toContain("\n");
      }

      // And the token is not in the URL, where an access log would keep it.
      expect(sent.url).toBe("/auth/v1/introspect");
      expect(sent.url).not.toContain("?");
    } finally {
      await center.close();
    }
  });

  it("sends the caller secret as one header and never in the body", async () => {
    const center = await startEchoCenter();
    try {
      await createIntrospector({ url: center.url, secret: SECRET }).introspect(
        "plain.token"
      );
      const sent = center.seen[0];
      expect(sent?.rawBody).toBe("token=plain.token");
      expect(sent?.rawBody).not.toContain(SECRET);
      expect(sent?.headerNames).toContain(SECRET_HEADER.toLowerCase());
    } finally {
      await center.close();
    }
  });
});

describe("bearerFrom never invents a credential", () => {
  it("reads a well-formed header", () => {
    expect(bearerFrom("Bearer abc")).toBe("abc");
    // The scheme is case-insensitive; the token is not touched at all.
    expect(bearerFrom("bearer AbC")).toBe("AbC");
    expect(bearerFrom("BEARER abc")).toBe("abc");
    expect(bearerFrom("  Bearer   abc  ")).toBe("abc");
  });

  it.each([
    ["nothing at all", null],
    ["undefined", undefined],
    ["an empty header", ""],
    ["whitespace only", "   "],
    ["the scheme alone", "Bearer"],
    ["the scheme and a space", "Bearer "],
    ["the scheme and only whitespace", "Bearer \t "],
    ["a bare token with no scheme", "abc"],
    ["another scheme", "Basic b3BlcmF0b3I6aHVudGVyMg=="],
    ["a scheme that merely starts with bearer", "Bearerish abc"],
  ] as const)("reads %s as no credential", (_name, header) => {
    expect(bearerFrom(header)).toBeNull();
  });

  it("does not concatenate a split header into a token", () => {
    // `rest.join("")` would answer "abcdef" — a credential nobody issued, sent
    // to the center as if a caller had presented it.
    expect(bearerFrom("Bearer abc def")).toBeNull();
    expect(bearerFrom("Bearer abc def ghi")).toBeNull();
    expect(bearerFrom("Bearer abc\tdef")).toBeNull();
  });

  it("reads a value carrying two credentials as no credential", () => {
    // NOT what two Authorization request headers produce — see the wire test
    // below. This is the shape a proxy that folds a repeated header hands on.
    // Picking either one would let a caller choose which of two credentials a
    // service verifies.
    expect(bearerFrom("Bearer abc, Bearer def")).toBeNull();
    // The array shape a framework may hand back for a repeated header.
    expect(bearerFrom(["Bearer abc", "Bearer def"])).toBeNull();
    expect(bearerFrom(["Bearer abc"])).toBe("abc");
  });
});

describe("two Authorization headers, as they really arrive", () => {
  /**
   * A previous revision of this file, of `core.ts` and of the README all said
   * that two `Authorization` lines reach Express joined as `"Bearer a, Bearer
   * b"` and therefore read as no credential. That is false: `Authorization` is
   * one of the headers Node's parser treats as single-valued, so a repeat is
   * DISCARDED and the first line wins. Nothing about the package's behaviour
   * changes, but the claim was wrong, so it is now tested on the wire with a
   * raw socket rather than asserted in a comment.
   *
   * What it meant was worse than the wrong comment: the adapter read the first
   * line and verified it, so a caller chose which of two credentials a service
   * saw. The adapter now counts lines in `rawHeaders` and reads more than one
   * as no credential — `authorization-lines.test.ts` drives that through real
   * Express. This block stays as the proof of what Node itself does.
   */
  const raw = async (lines: readonly string[]): Promise<Record<string, unknown>> => {
    const server = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          header: req.headers.authorization ?? null,
          rawCount: authorizationLines(req.rawHeaders),
        })
      );
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const { port } = server.address() as AddressInfo;
    try {
      const socket = connect(port, "127.0.0.1");
      await once(socket, "connect");
      socket.write(
        ["GET / HTTP/1.1", "Host: localhost", ...lines, "Connection: close", "", ""].join(
          "\r\n"
        )
      );
      let body = "";
      socket.setEncoding("utf8");
      socket.on("data", (chunk: string) => {
        body += chunk;
      });
      await once(socket, "end");
      return JSON.parse(body.split("\r\n\r\n")[1] ?? "{}") as Record<
        string,
        unknown
      >;
    } finally {
      server.close();
      await once(server, "close");
    }
  };

  it("keeps the first and discards the second — it does not join them", async () => {
    const seen = await raw([
      "Authorization: Bearer first.token",
      "Authorization: Bearer second.token",
    ]);
    // Both lines were on the wire...
    expect(seen.rawCount).toBe(2);
    // ...and the parsed header is the FIRST one, alone. Not "Bearer
    // first.token, Bearer second.token".
    expect(seen.header).toBe("Bearer first.token");
  });

  it("so the parsed value alone looks like one well-formed credential", async () => {
    // Which is why the parsed value cannot be the input on its own: bearerFrom
    // reads the first line as a credential, and only the raw count shows there
    // were two. A service behind a proxy that folds repeats instead gets the
    // comma value, which reads as none without any count.
    const seen = await raw([
      "Authorization: Bearer first.token",
      "Authorization: Bearer second.token",
    ]);
    expect(bearerFrom(seen.header as string)).toBe("first.token");
    expect(bearerFrom("Bearer first.token, Bearer second.token")).toBeNull();
  });
});

describe("isSafeMethod", () => {
  it.each(["GET", "HEAD", "OPTIONS", "get", "head", "options", "HeAd"])(
    "%s is safe",
    (method) => {
      expect(isSafeMethod(method)).toBe(true);
    }
  );

  it.each(["POST", "PUT", "PATCH", "DELETE", "post", "TRACE", "CONNECT", ""])(
    "%s is mutating",
    (method) => {
      expect(isSafeMethod(method)).toBe(false);
    }
  );
});

describe("the one-call timer", () => {
  it("is cleared on the success path, so nothing holds the event loop open", async () => {
    // N1: `clearTimeout` in the `finally` is not decoration. Without it a
    // process that finishes its work still waits out the full timeout before
    // exiting — a one-second tax on every short-lived script and on jest's own
    // teardown — and under load the pending timers accumulate.
    const center = await startEchoCenter();
    const setSpy = jest.spyOn(globalThis, "setTimeout");
    const clearSpy = jest.spyOn(globalThis, "clearTimeout");
    try {
      await createIntrospector({
        url: center.url,
        secret: SECRET,
        timeoutMs: DEFAULT_TIMEOUT_MS,
      }).introspect("plain.token");

      const scheduled = setSpy.mock.results
        .map((r) => r.value as unknown)
        .filter((v) => v !== undefined);
      expect(scheduled.length).toBeGreaterThan(0);
      const cleared = clearSpy.mock.calls.map((c) => c[0] as unknown);
      // Every timer this call scheduled was cleared again.
      for (const timer of scheduled) expect(cleared).toContain(timer);
    } finally {
      setSpy.mockRestore();
      clearSpy.mockRestore();
      await center.close();
    }
  });
});
