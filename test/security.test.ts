/**
 * @file The properties the fixture cannot observe from outside.
 *
 * Secrecy, redirect handling, a bounded read, and the absence of shared state.
 * None of these change a status code, so nothing in the fixture would catch
 * them regressing.
 */

import { createServer } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";

import { createIntrospector } from "../src/center";
import { createAuthorizer } from "../src/core";
import { loadIntrospectionConfig } from "../src/config";
import { MESSAGES } from "../src/messages";
import {
  startOversizedCenter,
  startRedirectingCenter,
  startStubCenter,
} from "./support/stubCenter";

const SECRET = "s3cr3t-introspection-value-never-logged";
const TOKEN = "operator.token.never.logged";

/** Captures everything written to a console or a std stream while `run` runs. */
const captureOutput = async (run: () => Promise<void>): Promise<string> => {
  const written: string[] = [];
  const consoleMethods = ["log", "info", "warn", "error", "debug", "trace"] as const;
  // eslint-disable-next-line @typescript-eslint/unbound-method -- saved only so it can be restored by assignment; never called unbound
  const originalConsole = consoleMethods.map((m) => [m, console[m]] as const);
  const originalStdout = process.stdout.write.bind(process.stdout);
  const originalStderr = process.stderr.write.bind(process.stderr);

  for (const method of consoleMethods) {
    console[method] = ((...args: unknown[]) => {
      written.push(args.map((a) => String(a)).join(" "));
    }) as typeof console.log;
  }
  process.stdout.write = ((chunk: unknown, ...rest: unknown[]) => {
    written.push(String(chunk));
    return originalStdout(chunk as string, ...(rest as []));
  });
  process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => {
    written.push(String(chunk));
    return originalStderr(chunk as string, ...(rest as []));
  });

  try {
    await run();
  } finally {
    for (const [method, fn] of originalConsole) {
      (console[method] as unknown) = fn;
    }
    process.stdout.write = originalStdout;
    process.stderr.write = originalStderr;
  }
  return written.join("\n");
};

describe("the token and the caller secret stay out of everything observable", () => {
  it("writes neither to any log line, on any path through the client", async () => {
    const centers = [
      await startStubCenter({ status: 200, body: '{"active":false}' }),
      await startStubCenter({ status: 500, body: '{"error":{"message":"boom"}}' }),
      await startStubCenter({ status: 401, body: '{"error":{"message":"nope"}}' }),
      await startStubCenter({ status: 200, body: "<html>not json</html>" }),
      await startStubCenter({ transport: "no-response" }),
    ];

    try {
      const output = await captureOutput(async () => {
        for (const center of centers) {
          const authorizer = createAuthorizer({ url: center.url, secret: SECRET });
          await authorizer.authorize({
            method: "POST",
            requires: "fleet:control",
            authorization: `Bearer ${TOKEN}`,
          });
        }
      });

      expect(output).not.toContain(SECRET);
      expect(output).not.toContain(TOKEN);
    } finally {
      for (const center of centers) await center.close();
    }
  });

  it("never throws, so neither can reach a caller's error handler", async () => {
    const center = await startStubCenter({ transport: "no-response" });
    try {
      const authorizer = createAuthorizer({ url: center.url, secret: SECRET });
      const decision = await authorizer.authorize({
        method: "POST",
        requires: "fleet:control",
        authorization: `Bearer ${TOKEN}`,
      });
      expect(decision).toEqual({
        outcome: "reject",
        status: 503,
        message: MESSAGES.centerUnavailable,
      });
    } finally {
      await center.close();
    }
  });

  it("keeps the secret out of a startup configuration error", () => {
    const env = {
      AUTH_INTROSPECTION_URL: "ftp://localhost:3005/auth/v1/introspect",
      AUTH_INTROSPECTION_SECRET: SECRET,
    };
    expect(() => loadIntrospectionConfig(env)).toThrow(/must use http or https/);
    try {
      loadIntrospectionConfig(env);
    } catch (error) {
      const rendered = `${(error as Error).message}\n${(error as Error).stack ?? ""}`;
      expect(rendered).not.toContain(SECRET);
    }
  });
});

describe("the caller secret never travels to a host the center named", () => {
  it("does not follow a redirect", async () => {
    const center = await startRedirectingCenter();
    try {
      const authorizer = createAuthorizer({ url: center.url, secret: SECRET });
      const decision = await authorizer.authorize({
        method: "POST",
        requires: "fleet:control",
        authorization: `Bearer ${TOKEN}`,
      });

      // A 3xx is simply not a 2xx, so it fails closed like any other bad
      // answer — and, crucially, the destination saw nothing.
      expect(decision).toEqual({
        outcome: "reject",
        status: 503,
        message: MESSAGES.centerUnavailable,
      });
      expect(center.requests).toHaveLength(1);
      expect(center.destination.requests).toHaveLength(0);
    } finally {
      await center.close();
    }
  });
});

describe("the center's answer is read under a cap", () => {
  it("gives up on an oversized body rather than buffering it", async () => {
    // Well past the 64 KiB default, and valid JSON if it were read to the end:
    // a client without the cap would answer `proceed` here.
    const center = await startOversizedCenter(400_000);
    try {
      const authorizer = createAuthorizer({ url: center.url, secret: SECRET });
      const decision = await authorizer.authorize({
        method: "POST",
        requires: "fleet:control",
        authorization: `Bearer ${TOKEN}`,
      });
      expect(decision).toEqual({
        outcome: "reject",
        status: 503,
        message: MESSAGES.centerUnavailable,
      });
    } finally {
      await center.close();
    }
  });

  it("accepts a body just under the cap it is given", async () => {
    const center = await startStubCenter({
      status: 200,
      body: JSON.stringify({
        active: true,
        sub: "user_padded",
        scope: "fleet:control",
        exp: 4102444800,
        kind: "operator",
      }),
    });
    try {
      const introspector = createIntrospector({
        url: center.url,
        secret: SECRET,
        maxResponseBytes: 4096,
      });
      const answer = await introspector.introspect(TOKEN);
      expect(answer.state).toBe("active");
    } finally {
      await center.close();
    }
  });
});

describe("a partial or wrongly typed answer is unavailable, never inactive", () => {
  const bad: [string, string][] = [
    ["missing sub", '{"active":true,"scope":"a","exp":1,"kind":"operator"}'],
    ["missing kind", '{"active":true,"sub":"user_a","scope":"a","exp":1}'],
    ["scope as null", '{"active":true,"sub":"user_a","scope":null,"exp":1,"kind":"operator"}'],
    ["missing exp", '{"active":true,"sub":"user_a","scope":"a","kind":"operator"}'],
    [
      "unknown kind",
      '{"active":true,"sub":"user_a","scope":"a","exp":1,"kind":"daemon"}',
    ],
    [
      "scope as an array",
      '{"active":true,"sub":"user_a","scope":["a"],"exp":1,"kind":"operator"}',
    ],
    ["active as a string", '{"active":"false"}'],
    ["active as a number", '{"active":1}'],
    ["active absent", "{}"],
    ["an array", "[]"],
    ["null", "null"],
    ["empty body", ""],
  ];

  it.each(bad)("%s is 503", async (_label, body) => {
    const center = await startStubCenter({ status: 200, body });
    try {
      const authorizer = createAuthorizer({ url: center.url, secret: SECRET });
      const decision = await authorizer.authorize({
        method: "POST",
        requires: "fleet:control",
        authorization: `Bearer ${TOKEN}`,
      });
      expect(decision).toEqual({
        outcome: "reject",
        status: 503,
        message: MESSAGES.centerUnavailable,
      });
    } finally {
      await center.close();
    }
  });
});

describe("an active answer with no scope key means no scopes", () => {
  // RFC 7662 makes `scope` optional, and auth-service omitted it for a
  // scopeless token until its PR #4. v1.1.0 answered 503 to every such
  // session: a signed-in guest could not reach a `session` route at all.
  const ABSENT = '{"active":true,"sub":"user_guest","exp":4102444800,"kind":"operator"}';

  it("lets a session route proceed with an empty scope list", async () => {
    const center = await startStubCenter({ status: 200, body: ABSENT });
    try {
      const authorizer = createAuthorizer({ url: center.url, secret: SECRET });
      const decision = await authorizer.authorize({
        method: "GET",
        requires: "session",
        authorization: `Bearer ${TOKEN}`,
      });
      expect(decision).toEqual({
        outcome: "proceed",
        identity: { sub: "user_guest", kind: "operator", scopes: [] },
      });
    } finally {
      await center.close();
    }
  });

  it("is still 403, not 503, on a route that needs a scope", async () => {
    const center = await startStubCenter({ status: 200, body: ABSENT });
    try {
      const authorizer = createAuthorizer({ url: center.url, secret: SECRET });
      const decision = await authorizer.authorize({
        method: "POST",
        requires: "fleet:control",
        authorization: `Bearer ${TOKEN}`,
      });
      expect(decision).toEqual({
        outcome: "reject",
        status: 403,
        message: MESSAGES.missingScope,
      });
    } finally {
      await center.close();
    }
  });
});

describe("concurrent requests share no state", () => {
  it("gives each caller its own identity", async () => {
    // A center that answers from the token it was given, so a client holding
    // one shared buffer or one in-flight promise answers the wrong caller.
    const server = createServer((req, res) => {
      void (async () => {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk as Buffer);
        const token = new URLSearchParams(
          Buffer.concat(chunks).toString("utf8")
        ).get("token");
        // Staggered so the answers cannot arrive in request order.
        setTimeout(() => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              active: true,
              sub: `user_${String(token)}`,
              scope: `scope:${String(token)}`,
              exp: 4102444800,
              kind: Number(token) % 2 === 0 ? "operator" : "machine",
            })
          );
        }, ((Number(token) * 7) % 11) + 1);
      })();
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const { port } = server.address() as AddressInfo;

    try {
      const authorizer = createAuthorizer({
        url: `http://127.0.0.1:${String(port)}/auth/v1/introspect`,
        secret: SECRET,
      });
      const indices = Array.from({ length: 40 }, (_, i) => i);
      const decisions = await Promise.all(
        indices.map((i) =>
          authorizer.authorize({
            method: "POST",
            requires: `scope:${String(i)}`,
            authorization: `Bearer ${String(i)}`,
          })
        )
      );

      decisions.forEach((decision, i) => {
        expect(decision.outcome).toBe("proceed");
        if (decision.outcome !== "proceed") return;
        expect(decision.identity).toEqual({
          sub: `user_${String(i)}`,
          kind: i % 2 === 0 ? "operator" : "machine",
          scopes: [`scope:${String(i)}`],
        });
      });
    } finally {
      server.closeAllConnections();
      server.close();
      await once(server, "close");
    }
  });
});
