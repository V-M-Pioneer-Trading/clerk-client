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
  MESSAGES,
  secured,
  type HandlerLike,
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

  app = server.listen(0, "127.0.0.1");
  await once(app, "listening");
  appPort = (app.address() as AddressInfo).port;
});

afterAll(async () => {
  app.closeAllConnections();
  app.close();
  center.closeAllConnections();
  center.close();
  await Promise.all([once(app, "close"), once(center, "close")]);
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
  headerLines: readonly string[]
): Promise<RawResponse> => {
  const socket = connect(appPort, "127.0.0.1");
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

describe("authorizationLines", () => {
  it("counts names at even indices, in any case", () => {
    expect(authorizationLines([])).toBe(0);
    expect(authorizationLines(["Host", "x"])).toBe(0);
    expect(authorizationLines(["Authorization", "Bearer a"])).toBe(1);
    expect(
      authorizationLines(["authorization", "Bearer a", "AuThOrIzAtIoN", ""])
    ).toBe(2);
  });

  it("never counts a value", () => {
    expect(authorizationLines(["X-Note", "authorization"])).toBe(0);
    expect(
      authorizationLines(["X-Note", "Authorization", "Authorization", "Bearer a"])
    ).toBe(1);
  });

  it("counts nothing in something that is not an array", () => {
    expect(authorizationLines(undefined as unknown as string[])).toBe(0);
  });
});

describe("a request with no rawHeaders", () => {
  it("is read as no credential rather than trusted to carry one line", async () => {
    // A JavaScript caller, or a cast, can hand the adapter a request without
    // `rawHeaders`. Nothing can be counted, so nothing is read.
    const auth = createExpressAuth({ url: centerUrl, secret: SECRET });
    const handler: HandlerLike = auth.requireSession();
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
      handler(
        {
          method: "GET",
          header: () => "Bearer a.token",
        } as unknown as Parameters<HandlerLike>[0],
        res,
        () => resolve()
      );
      setTimeout(resolve, 200);
    });
    expect(status).toBe(401);
    expect(asked).toEqual([]);
  });
});
