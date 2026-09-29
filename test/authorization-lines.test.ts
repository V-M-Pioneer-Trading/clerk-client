/**
 * @file Two `Authorization` lines are never a credential.
 *
 * Node's HTTP parser treats `Authorization` as single-valued: a repeated line
 * is DISCARDED and the first one kept, so `req.headers.authorization` for
 * `Bearer a` + `Bearer b` is `"Bearer a"`, and for an empty line + `Bearer b`
 * it is `""`. An adapter that reads only that value lets a caller choose which
 * of two credentials is verified by choosing their order, or turn a
 * credentialed request into an anonymous one. `meta`'s spec says two lines are
 * no credential and the center is not called.
 *
 * A client library cannot send two `Authorization` headers — supertest,
 * `fetch` and `http.request` all fold or replace them — so every request here
 * is written to a raw socket, byte for byte, against a real Express app. The
 * center is a real HTTP stub that would call BOTH tokens valid, so any request
 * that reached it would succeed and any call is counted.
 */

import { createServer, type Server } from "node:http";
import { once } from "node:events";
import { connect, type AddressInfo } from "node:net";
import express from "express";

import {
  actorOf,
  authorizationLines,
  createExpressAuth,
  createLaneDeriver,
  MESSAGES,
  secured,
  type HandlerLike,
  type RawHeaderSource,
  type ResponseLike,
} from "../src/index";

const SECRET = "authorization-lines-suite-secret";

/** Both tokens are active and carry the scope: reaching the center is success. */
const ANSWERS: Record<string, unknown> = {
  "a.token": {
    active: true,
    sub: "user_a",
    scope: "fleet:control",
    exp: 4102444800,
    kind: "operator",
  },
  "b.token": {
    active: true,
    sub: "user_b",
    scope: "fleet:control",
    exp: 4102444800,
    kind: "operator",
  },
};

let center: Server;
let centerUrl: string;
const asked: string[] = [];

let app: Server;
let appPort: number;
/** The same app on a server with `maxHeadersCount = 0`: no header limit. */
let unlimited: Server;
let unlimitedPort: number;

beforeAll(async () => {
  center = createServer((req, res) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const token =
        new URLSearchParams(Buffer.concat(chunks).toString("utf8")).get("token") ??
        "";
      asked.push(token);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(ANSWERS[token] ?? { active: false }));
    })();
  });
  center.listen(0, "127.0.0.1");
  await once(center, "listening");
  centerUrl = `http://127.0.0.1:${(center.address() as AddressInfo).port}/auth/v1/introspect`;

  const auth = createExpressAuth({ url: centerUrl, secret: SECRET });
  const whoami = (_req: unknown, res: ResponseLike): void => {
    res.status(200).json({ actor: actorOf(res) });
  };

  // Per-route declarations, behind secured(): automation-service's shape.
  const api = secured(express.Router());
  api.post("/scoped", auth.requireScope("fleet:control"), whoami);
  api.get("/session", auth.requireSession(), whoami);
  api.get("/public", auth.allowPublic(), whoami);
  api.get("/health", auth.ignoreCredentials(), whoami);

  // A router-level guard over a plain router: fleet-service's shape.
  const generated = express.Router();
  generated.get("/ships", whoami);

  const server = express();
  server.use("/api", api);
  server.use("/guarded", auth.guard(() => "session"), generated);

  // st-gateway's shape: no adapter, just the README's recipe in front of the
  // lane deriver. Both tokens are operators, so reaching the center is
  // "interactive" and anything else is "background".
  const deriver = createLaneDeriver({ url: centerUrl, secret: SECRET });
  server.get("/lane", (req, res) => {
    const header = authorizationLines(req) === 1 ? req.header("Authorization") : null;
    void deriver.derive(header).then((lane) => res.json({ lane }));
  });

  app = server.listen(0, "127.0.0.1");
  await once(app, "listening");
  appPort = (app.address() as AddressInfo).port;

  unlimited = createServer(server);
  unlimited.maxHeadersCount = 0;
  unlimited.listen(0, "127.0.0.1");
  await once(unlimited, "listening");
  unlimitedPort = (unlimited.address() as AddressInfo).port;
});

afterAll(async () => {
  for (const server of [app, unlimited, center]) {
    server.closeAllConnections();
    server.close();
  }
  await Promise.all([once(app, "close"), once(unlimited, "close"), once(center, "close")]);
});

beforeEach(() => {
  asked.length = 0;
});

interface RawResponse {
  readonly status: number;
  readonly body: Record<string, unknown>;
}

/**
 * One request, written to the socket exactly as given. `headerLines` are raw
 * header lines, so two `Authorization` lines really are two lines on the wire.
 */
const raw = async (
  method: "GET" | "POST",
  path: string,
  headerLines: readonly string[],
  port: number = appPort
): Promise<RawResponse> => {
  const socket = connect(port, "127.0.0.1");
  await once(socket, "connect");
  socket.write(
    [
      `${method} ${path} HTTP/1.1`,
      "Host: localhost",
      ...headerLines,
      ...(method === "POST" ? ["Content-Length: 0"] : []),
      "Connection: close",
      "",
      "",
    ].join("\r\n")
  );
  let received = "";
  socket.setEncoding("utf8");
  socket.on("data", (chunk: string) => {
    received += chunk;
  });
  await once(socket, "end");

  const [head = "", ...rest] = received.split("\r\n\r\n");
  const status = Number(/^HTTP\/1\.1 (\d{3})/.exec(head)?.[1] ?? "0");
  // Express answers JSON with a Content-Length, never chunked, so the body is
  // everything after the head.
  const text = rest.join("\r\n\r\n");
  return { status, body: text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {} };
};

const missingToken = { error: { message: MESSAGES.missingToken } };

describe("two Authorization lines on the wire are no credential", () => {
  const TWO_BEARERS = ["Authorization: Bearer a.token", "Authorization: Bearer b.token"];

  it("answers 401 on a scoped POST, without asking the center", async () => {
    const response = await raw("POST", "/api/scoped", TWO_BEARERS);
    // Without the rule this is 200 as user_a: Node hands the adapter
    // "Bearer a.token" and the second line is gone.
    expect(response.status).toBe(401);
    expect(response.body).toEqual(missingToken);
    expect(asked).toEqual([]);
  });

  it("answers 401 on a session route, without asking the center", async () => {
    const response = await raw("GET", "/api/session", TWO_BEARERS);
    expect(response.status).toBe(401);
    expect(response.body).toEqual(missingToken);
    expect(asked).toEqual([]);
  });

  it("answers 401 behind a router-level guard(), without asking the center", async () => {
    const response = await raw("GET", "/guarded/ships", TWO_BEARERS);
    expect(response.status).toBe(401);
    expect(response.body).toEqual(missingToken);
    expect(asked).toEqual([]);
  });

  it("serves an allowPublic() read as a visitor, without asking the center", async () => {
    const response = await raw("GET", "/api/public", TWO_BEARERS);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ actor: null });
    expect(asked).toEqual([]);
  });

  it("leaves an ignoreCredentials() route alone: 200, no center", async () => {
    const response = await raw("GET", "/api/health", TWO_BEARERS);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ actor: null });
    expect(asked).toEqual([]);
  });
});

describe("an empty line is still a line", () => {
  it.each([
    ["a bearer, then an empty line", ["Authorization: Bearer a.token", "Authorization: "]],
    // Without the rule this one is the other direction: Node keeps "" and the
    // credentialed request becomes a visitor on public routes.
    ["an empty line, then a bearer", ["Authorization: ", "Authorization: Bearer b.token"]],
  ] as const)("%s: 401 on a scoped POST, visitor on a public GET, no center", async (_name, lines) => {
    const scoped = await raw("POST", "/api/scoped", lines);
    expect(scoped.status).toBe(401);
    expect(scoped.body).toEqual(missingToken);

    const open = await raw("GET", "/api/public", lines);
    expect(open.status).toBe(200);
    expect(open.body).toEqual({ actor: null });

    expect(asked).toEqual([]);
  });
});

describe("the header name is counted case-insensitively", () => {
  it("counts two lowercase authorization lines", async () => {
    const response = await raw("POST", "/api/scoped", [
      "authorization: Bearer a.token",
      "authorization: Bearer b.token",
    ]);
    expect(response.status).toBe(401);
    expect(asked).toEqual([]);
  });

  it("counts one line of each spelling", async () => {
    const response = await raw("POST", "/api/scoped", [
      "authorization: Bearer a.token",
      "AUTHORIZATION: Bearer b.token",
    ]);
    expect(response.status).toBe(401);
    expect(asked).toEqual([]);
  });
});

describe("one line is still a credential", () => {
  it.each([
    ["Authorization"],
    ["authorization"],
    ["AUTHORIZATION"],
  ])("%s: Bearer a.token is verified and served", async (name) => {
    const scoped = await raw("POST", "/api/scoped", [`${name}: Bearer a.token`]);
    expect(scoped.status).toBe(200);
    expect(scoped.body).toEqual({ actor: "user_a" });
    expect(asked).toEqual(["a.token"]);
  });

  it("verifies one line on a public read too", async () => {
    const response = await raw("GET", "/api/public", ["Authorization: Bearer b.token"]);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ actor: "user_b" });
    expect(asked).toEqual(["b.token"]);
  });

  it("does not count an unrelated header whose VALUE says authorization", async () => {
    const response = await raw("POST", "/api/scoped", [
      "X-Note: authorization",
      "Authorization: Bearer a.token",
    ]);
    expect(response.status).toBe(200);
    expect(asked).toEqual(["a.token"]);
  });

  it("serves a request with no Authorization line as it always did", async () => {
    expect((await raw("POST", "/api/scoped", [])).status).toBe(401);
    expect((await raw("GET", "/api/public", [])).body).toEqual({ actor: null });
    expect(asked).toEqual([]);
  });
});

describe("three lines are not one either", () => {
  it("answers 401 on a scoped POST, without asking the center", async () => {
    // Pins "exactly one", not "not two": a rule written as `=== 2` would pass
    // every two-line case above and serve this.
    const response = await raw("POST", "/api/scoped", [
      "Authorization: Bearer a.token",
      "Authorization: Bearer b.token",
      "Authorization: Bearer a.token",
    ]);
    expect(response.status).toBe(401);
    expect(response.body).toEqual(missingToken);
    expect(asked).toEqual([]);
  });
});

/**
 * Node stops appending to `rawHeaders` (and `headers`) once it holds
 * `2 × server.maxHeadersCount` entries (2000 by default), so a second
 * `Authorization` line sent after ~1000 filler lines is not there to count.
 * Five kilobytes of `x: 1`, far under the 16 KiB `maxHeaderSize`.
 */
const filler = (count: number): string[] => Array.from({ length: count }, () => "x: 1");
const smuggled = (count: number): string[] => [
  "Authorization: Bearer a.token",
  ...filler(count),
  "Authorization: Bearer b.token",
];

describe("a second line hidden past Node's header limit", () => {
  it("is refused on a scoped POST: 401, no center", async () => {
    // Without the limit check this was 200 as user_a: rawHeaders held one
    // Authorization line, because the second was never recorded.
    const response = await raw("POST", "/api/scoped", smuggled(1100));
    expect(response.status).toBe(401);
    expect(response.body).toEqual(missingToken);
    expect(asked).toEqual([]);
  });

  it("is refused behind a router-level guard(): 401, no center", async () => {
    const response = await raw("GET", "/guarded/ships", smuggled(1100));
    expect(response.status).toBe(401);
    expect(asked).toEqual([]);
  });

  it("serves an allowPublic() read as a visitor, no center", async () => {
    const response = await raw("GET", "/api/public", smuggled(1100));
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ actor: null });
    expect(asked).toEqual([]);
  });

  it("puts the README lane recipe in the background lane, no center", async () => {
    const response = await raw("GET", "/lane", smuggled(1100));
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ lane: "background" });
    expect(asked).toEqual([]);
  });

  it("refuses even ONE line once the request reaches the limit", async () => {
    // At the limit, a request that stopped short cannot be told from one that
    // went past it (Node records lines in batches), so both are refused.
    // 996 fillers + Host + Authorization + Content-Length + Connection =
    // 1000 lines = 2000 entries.
    const response = await raw("POST", "/api/scoped", [
      "Authorization: Bearer a.token",
      ...filler(996),
    ]);
    expect(response.status).toBe(401);
    expect(asked).toEqual([]);
  });

  it("verifies one line just under the limit", async () => {
    // One line fewer: 999 lines, 1998 entries, every one recorded. The POST
    // carries a Content-Length line the GET below does not.
    const scoped = await raw("POST", "/api/scoped", [
      "Authorization: Bearer a.token",
      ...filler(995),
    ]);
    expect(scoped.status).toBe(200);
    expect(scoped.body).toEqual({ actor: "user_a" });

    const lane = await raw("GET", "/lane", ["Authorization: Bearer b.token", ...filler(996)]);
    expect(lane.body).toEqual({ lane: "interactive" });
    expect(asked).toEqual(["a.token", "b.token"]);
  });

  it("counts both lines on a server with maxHeadersCount = 0 (no limit)", async () => {
    // The limit is read from the server, not assumed: with it lifted, Node
    // records all 1100 fillers and the second line, and the count is exact.
    const scoped = await raw("POST", "/api/scoped", smuggled(1100), unlimitedPort);
    expect(scoped.status).toBe(401);
    expect(scoped.body).toEqual(missingToken);

    const lane = await raw("GET", "/lane", smuggled(1100), unlimitedPort);
    expect(lane.body).toEqual({ lane: "background" });
    expect(asked).toEqual([]);

    // And one line among the same filler is still a credential there.
    const one = await raw(
      "POST",
      "/api/scoped",
      ["Authorization: Bearer a.token", ...filler(1100)],
      unlimitedPort
    );
    expect(one.status).toBe(200);
    expect(asked).toEqual(["a.token"]);
  });
});

describe("authorizationLines", () => {
  const of = (rawHeaders: unknown, socket?: unknown): number =>
    authorizationLines({ rawHeaders, socket } as RawHeaderSource);

  it("counts names at even indices, in any case", () => {
    expect(of([])).toBe(0);
    expect(of(["Host", "x"])).toBe(0);
    expect(of(["Authorization", "Bearer a"])).toBe(1);
    expect(of(["authorization", "Bearer a", "AuThOrIzAtIoN", ""])).toBe(2);
    expect(
      of(["a", "1", "Authorization", "x", "b", "2", "authorization", "y", "AUTHORIZATION", "z"])
    ).toBe(3);
  });

  it("never counts a value", () => {
    expect(of(["X-Note", "authorization"])).toBe(0);
    expect(of(["X-Note", "Authorization", "Authorization", "Bearer a"])).toBe(1);
  });

  it.each([
    ["no rawHeaders at all", undefined],
    ["a string", "Authorization: Bearer a"],
    ["an odd-length list", ["Authorization"]],
    ["a name at an odd offset only", ["Bearer a", "Authorization", "x"]],
    ["a non-string name", [7, "Bearer a"]],
  ])("answers Infinity, never one, for %s", (_name, rawHeaders) => {
    expect(of(rawHeaders)).toBe(Number.POSITIVE_INFINITY);
  });

  it("answers Infinity for a bare array, the pre-release call shape", () => {
    // `authorizationLines(req.rawHeaders)`: the array has no `rawHeaders` of
    // its own, so it reads as uncountable rather than as zero or one.
    expect(authorizationLines(["Authorization", "a"] as unknown as RawHeaderSource)).toBe(
      Number.POSITIVE_INFINITY
    );
    expect(authorizationLines(undefined as unknown as RawHeaderSource)).toBe(
      Number.POSITIVE_INFINITY
    );
  });

  it("reads the limit off socket.server.maxHeadersCount the way Node does", () => {
    const entries = (n: number): string[] =>
      Array.from({ length: n }, (_v, i) => (i % 2 === 0 ? "x" : "1"));
    const server = (maxHeadersCount: unknown) => ({ server: { maxHeadersCount } });

    // Unset, null, or no server to read: Node's default, 2000 entries.
    expect(of(entries(1998))).toBe(0);
    expect(of(entries(2000))).toBe(Number.POSITIVE_INFINITY);
    expect(of(entries(2000), server(null))).toBe(Number.POSITIVE_INFINITY);
    expect(of(entries(2000), {})).toBe(Number.POSITIVE_INFINITY);
    // A number: twice it.
    expect(of(entries(18), server(10))).toBe(0);
    expect(of(entries(20), server(10))).toBe(Number.POSITIVE_INFINITY);
    expect(of(entries(3998), server(2000))).toBe(0);
    // Zero, negative or NaN: `<< 1` is <= 0, which Node reads as no limit.
    expect(of(entries(5000), server(0))).toBe(0);
    expect(of(entries(5000), server(-1))).toBe(0);
    expect(of(entries(5000), server(Number.NaN))).toBe(0);
  });
});

/** Runs one adapter handler against a hand-made request, and reports the status. */
const statusFor = async (request: unknown): Promise<number> => {
  const handler: HandlerLike = createExpressAuth({
    url: centerUrl,
    secret: SECRET,
  }).requireSession();
  let status = 0;
  const res = {
    locals: {},
    status(code: number) {
      status = code;
      return res;
    },
    json: () => undefined,
  };
  await new Promise<void>((resolve) => {
    handler(request as Parameters<HandlerLike>[0], res, () => {
      status = 200;
      resolve();
    });
    setTimeout(resolve, 200);
  });
  return status;
};

describe("a request whose raw lines do not account for its header", () => {
  it("is no credential when it has no rawHeaders", async () => {
    // A JavaScript caller, or a cast, can hand the adapter a request without
    // `rawHeaders`. Nothing can be counted, so nothing is read.
    expect(await statusFor({ method: "GET", header: () => "Bearer a.token" })).toBe(401);
    expect(asked).toEqual([]);
  });

  it("is no credential when it has zero raw lines but header() answers", async () => {
    // Nothing on the wire carried that value, so something in the process put
    // it there. Middleware that sets req.headers.authorization is unsupported.
    expect(
      await statusFor({ method: "GET", rawHeaders: [], header: () => "Bearer a.token" })
    ).toBe(401);
    expect(asked).toEqual([]);
  });

  it("is no credential when the only Authorization name is at an odd offset", async () => {
    expect(
      await statusFor({
        method: "GET",
        rawHeaders: ["Bearer a.token", "Authorization"],
        header: () => "Bearer a.token",
      })
    ).toBe(401);
    expect(asked).toEqual([]);
  });

  it("is a credential when one raw line and header() agree", async () => {
    expect(
      await statusFor({
        method: "GET",
        rawHeaders: ["Authorization", "Bearer a.token"],
        header: () => "Bearer a.token",
      })
    ).toBe(200);
    expect(asked).toEqual(["a.token"]);
  });
});
