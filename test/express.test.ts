/**
 * @file The Express 4 adapter, in the two shapes the consumers have.
 *
 * automation-service and st-gateway decorate routes individually, which is the
 * shape this package now leads with: declarations at registration, bound by
 * Express's own matcher, behind a `secured()` router that refuses an
 * undeclared route at startup.
 *
 * fleet-service cannot do that — tsoa generates its router, so there is no
 * call site to put a declaration in — and keeps a router-level `guard()` whose
 * resolver is a function of the **method alone**. That shape is
 * path-independent and therefore immune to every matcher bug a path-keyed
 * table has; `routing.test.ts` is where those bugs are pinned.
 */

import { createServer, type Server } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import express, { type Express, type NextFunction, type Request, type RequestHandler, type Response } from "express";
import request from "supertest";

import {
  actorOf,
  createExpressAuth,
  type HandlerLike,
  hasScope,
  identityOf,
  kindOf,
  passthrough,
  secured,
} from "../src/express";
import { MESSAGES } from "../src/messages";

const SECRET = "express-suite-secret";

/** Answers from a small table keyed on the token, like the center would. */
const ANSWERS: Record<string, unknown> = {
  "operator.token": {
    active: true,
    sub: "user_operator",
    scope: "fleet:control universe:refresh",
    exp: 4102444800,
    kind: "operator",
  },
  "machine.token": {
    active: true,
    sub: "mch_machine",
    scope: "fleet:control",
    exp: 4102444800,
    kind: "machine",
  },
  // A `user_` subject the center calls a machine: the fence must follow the
  // center, not the prefix.
  "disagreeing.token": {
    active: true,
    sub: "user_operator",
    scope: "fleet:control",
    exp: 4102444800,
    kind: "machine",
  },
  "guest.token": {
    active: true,
    sub: "user_guest",
    scope: "",
    exp: 4102444800,
    kind: "operator",
  },
  "expired.token": { active: false },
};

let center: Server;
let centerUrl: string;

beforeAll(async () => {
  center = createServer((req, res) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const token =
        new URLSearchParams(Buffer.concat(chunks).toString("utf8")).get("token") ??
        "";
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(ANSWERS[token] ?? { active: false }));
    })();
  });
  center.listen(0, "127.0.0.1");
  await once(center, "listening");
  const { port } = center.address() as AddressInfo;
  centerUrl = `http://127.0.0.1:${String(port)}/auth/v1/introspect`;
});

afterAll(async () => {
  center.closeAllConnections();
  center.close();
  await once(center, "close");
});

export const auth = () => createExpressAuth({ url: centerUrl, secret: SECRET });

/**
 * fleet-service's shape: a generated router behind one `use`-mounted guard
 * whose resolver reads the method and nothing else.
 *
 * Note what is NOT here any more: a `` table[`${req.method} ${req.path}`] ??
 * "none" `` resolver. `req.path` inside this router is `/cooldown`, not
 * `/api/fleet/v1/cooldown`, and a miss used to mean "public". Both are gone.
 */
const fleetApp = (): Express => {
  const app = express();
  const a = auth();

  // Public surface, declared out loud, outside the guarded router.
  app.get("/health", a.allowPublic(), (_req, res) => {
    res.json({ actor: actorOf(res) });
  });

  const api = express.Router();
  api.use(
    a.guard(({ method }) => (method === "GET" ? "session" : "fleet:control"))
  );
  api.get("/cooldown", (_req, res) => {
    res.json({ actor: actorOf(res), identity: identityOf(res) });
  });
  api.post("/ships/navigate", (_req, res) => {
    res.json({ actor: actorOf(res), kind: kindOf(res) });
  });
  // Nobody wrote a declaration for this one, and it does not matter: the
  // guard covers the whole router by method, so it is a mutation and needs
  // the scope. That is what a method-only resolver buys.
  app.use("/api/fleet/v1", api);
  return app;
};

/** automation-service's shape: per-route declarations behind `secured()`. */
const automationApp = (): Express => {
  const app = express();
  const a = auth();
  const api = secured(express.Router());

  api.get("/health", a.allowPublic(), (_req, res) => {
    res.json({ actor: actorOf(res) });
  });
  api.get("/targets", a.requireSession(), (_req, res) => {
    res.json({ actor: actorOf(res), scopes: identityOf(res)?.scopes });
  });
  api.post("/targets", a.requireScope("fleet:control"), (_req, res) => {
    res.json({ actor: actorOf(res) });
  });
  api.put("/knobs/alert", a.requireScope("fleet:control"), (_req, res) => {
    // The fence keys on the center's `kind`, never on the subject prefix or on
    // the presence of a header — after decision 21 every caller presents one.
    if (kindOf(res) === "machine") {
      res.status(403).json({ error: { message: MESSAGES.missingScope } });
      return;
    }
    res.json({ actor: actorOf(res), refreshes: hasScope(res, "universe:refresh") });
  });

  app.use("/api/automation/v1", api);
  return app;
};

describe("router-level guard (fleet-service's shape)", () => {
  it("serves the declared-public health route to a visitor", async () => {
    const response = await request(fleetApp()).get("/health");
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ actor: null });
  });

  it("authorizes a declared mutation and hands the handler the identity", async () => {
    const response = await request(fleetApp())
      .post("/api/fleet/v1/ships/navigate")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ actor: "user_operator", kind: "operator" });
  });

  it("401s a read route with no header", async () => {
    const response = await request(fleetApp()).get("/api/fleet/v1/cooldown");
    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: { message: MESSAGES.missingToken } });
  });

  it("lets a scopeless session read, and refuses it the mutation", async () => {
    const read = await request(fleetApp())
      .get("/api/fleet/v1/cooldown")
      .set("Authorization", "Bearer guest.token");
    expect(read.status).toBe(200);
    expect((read.body as Record<string, unknown>).actor).toBe("user_guest");

    const write = await request(fleetApp())
      .post("/api/fleet/v1/ships/navigate")
      .set("Authorization", "Bearer guest.token");
    expect(write.status).toBe(403);
    expect(write.body).toEqual({ error: { message: MESSAGES.missingScope } });
  });

  it("401s a presented token the center rejects, even on a public route", async () => {
    const response = await request(fleetApp())
      .get("/health")
      .set("Authorization", "Bearer expired.token");
    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: { message: MESSAGES.invalidSession },
    });
  });
});

describe("per-route declarations (automation-service's shape)", () => {
  it("lets a scopeless session through a session route", async () => {
    const response = await request(automationApp())
      .get("/api/automation/v1/targets")
      .set("Authorization", "Bearer guest.token");
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ actor: "user_guest", scopes: [] });
  });

  it("403s a session missing the route's scope without naming it", async () => {
    const response = await request(automationApp())
      .post("/api/automation/v1/targets")
      .set("Authorization", "Bearer guest.token");
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: { message: MESSAGES.missingScope } });
    expect(JSON.stringify(response.body)).not.toContain("fleet:control");
  });

  it("records the actor for a machine caller", async () => {
    const response = await request(automationApp())
      .post("/api/automation/v1/targets")
      .set("Authorization", "Bearer machine.token");
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ actor: "mch_machine" });
  });

  it("fences a knob on the center's kind, not on the subject prefix", async () => {
    const asMachine = await request(automationApp())
      .put("/api/automation/v1/knobs/alert")
      .set("Authorization", "Bearer disagreeing.token");
    expect(asMachine.status).toBe(403);

    const asOperator = await request(automationApp())
      .put("/api/automation/v1/knobs/alert")
      .set("Authorization", "Bearer operator.token");
    expect(asOperator.status).toBe(200);
    expect(asOperator.body).toEqual({ actor: "user_operator", refreshes: true });
  });

  it("serves a route declared allowPublic() to a visitor", async () => {
    const response = await request(automationApp()).get(
      "/api/automation/v1/health"
    );
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ actor: null });
  });
});

/**
 * A cors-like middleware: sets the CORS headers and answers a preflight
 * itself, which is what `cors()` does. Written inline rather than adding a
 * dependency — what is under test is mount ORDER, not that package.
 */
export const corsish = (): RequestHandler => (req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Authorization");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
};

/** A `ResponseLike` that records what the guard did to it. */
interface FakeResponse {
  locals: Record<string, unknown>;
  statusCode?: number;
  body?: unknown;
  status(code: number): FakeResponse;
  json(body: unknown): unknown;
}

const fakeResponse = (): FakeResponse => {
  const res: FakeResponse = {
    locals: {},
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(body: unknown) {
      res.body = body;
      return body;
    },
  };
  return res;
};

/** Runs one guard against a hand-made request, and waits for it to settle. */
const runHandler = (
  handler: HandlerLike,
  req: { method: string; authorization?: string },
  res: FakeResponse
): Promise<{ nexted: boolean; error: unknown }> =>
  new Promise((resolve) => {
    let settled = false;
    const finish = (nexted: boolean, error: unknown): void => {
      if (settled) return;
      settled = true;
      resolve({ nexted, error });
    };
    handler(
      {
        method: req.method,
        header: (name: string) =>
          name.toLowerCase() === "authorization" ? req.authorization : undefined,
        rawHeaders:
          req.authorization === undefined ? [] : ["Authorization", req.authorization],
      },
      res,
      (error?: unknown) => { finish(true, error); }
    );
    // A rejection answers on `res` instead of calling next; give the timers
    // and the microtask queue a turn before concluding nothing happened.
    setTimeout(() => { finish(false, undefined); }, 100);
  });

describe("safe methods (meta fixture v2)", () => {
  it("serves HEAD on a declared-public route to a visitor", async () => {
    // Express dispatches HEAD /health to the GET /health handler, and the
    // declaration attached to that route comes with it. Treating HEAD as
    // mutating answers 500 here and breaks every health probe.
    const response = await request(fleetApp()).head("/health");
    expect(response.status).toBe(200);
  });

  it("resolves a HEAD through the GET the resolver would be asked about", async () => {
    // A method-only resolver that named GET explicitly must still govern a
    // HEAD of the same route: `asGet` is what makes the resolver see "GET".
    const denied = await request(fleetApp()).head("/api/fleet/v1/cooldown");
    expect(denied.status).toBe(401);

    const allowed = await request(fleetApp())
      .head("/api/fleet/v1/cooldown")
      .set("Authorization", "Bearer guest.token");
    expect(allowed.status).toBe(200);
  });

  it("401s HEAD on a per-route declaration, the same as GET", async () => {
    const response = await request(automationApp()).head(
      "/api/automation/v1/targets"
    );
    expect(response.status).toBe(401);
  });

  it("serves HEAD on a route declared allowPublic()", async () => {
    const response = await request(automationApp()).head(
      "/api/automation/v1/health"
    );
    expect(response.status).toBe(200);
  });

  it("lets a preflight through when cors is mounted BEFORE the guard", async () => {
    // The documented order: the preflight never reaches the guard at all,
    // which is the only reason preflight works. It does NOT work because the
    // guard waves OPTIONS through — see routing.test.ts.
    const app = express();
    app.use(corsish());
    const api = secured(express.Router());
    api.post("/targets", auth().requireScope("fleet:control"), (_req, res) => {
      res.json({ ran: true });
    });
    app.use(api);

    const response = await request(app)
      .options("/targets")
      .set("Origin", "https://dashboard.example")
      .set("Access-Control-Request-Method", "POST");
    expect(response.status).toBe(204);
    expect(response.headers["access-control-allow-origin"]).toBe("*");
  });

  it("breaks the preflight when cors is mounted AFTER the router", async () => {
    // Why the order in the README is an instruction and not a preference.
    //
    // Mounted the other way, the preflight never reaches cors at all: an
    // Express router answers an OPTIONS that matches a path but no method
    // ITSELF, with a 200 and an `Allow` header, and that is the end of the
    // request. The answer carries no `Access-Control-Allow-Origin`, so the
    // browser fails the preflight and the real request is never sent.
    //
    // Nothing is authorized away here — no handler ran and no declaration was
    // skipped — but the cross-origin call is broken, which is the symptom
    // somebody would come back and "fix" by waving OPTIONS past the guard.
    // Pinned so that the fix is known to be the mount order instead.
    const app = express();
    const api = secured(express.Router());
    api.post("/targets", auth().requireScope("fleet:control"), (_req, res) => {
      res.json({ ran: true });
    });
    app.use(api);
    app.use(corsish());

    const response = await request(app)
      .options("/targets")
      .set("Origin", "https://dashboard.example")
      .set("Access-Control-Request-Method", "POST");
    expect(response.status).toBe(200);
    expect(response.headers.allow).toContain("POST");
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("answers the preflight with cors headers when cors is mounted FIRST", async () => {
    // The same app, the one mount swapped. This is the arrangement all three
    // consumers already have (`app.use(cors())` is their first middleware),
    // and it is why the preflight keeps working without the guard abdicating.
    const app = express();
    app.use(corsish());
    const api = secured(express.Router());
    api.post("/targets", auth().requireScope("fleet:control"), (_req, res) => {
      res.json({ ran: true });
    });
    app.use(api);

    const response = await request(app)
      .options("/targets")
      .set("Origin", "https://dashboard.example")
      .set("Access-Control-Request-Method", "POST");
    expect(response.status).toBe(204);
    expect(response.headers["access-control-allow-origin"]).toBe("*");
  });

  it("still guards the real request that follows the preflight", async () => {
    const app = express();
    app.use(corsish());
    const api = secured(express.Router());
    api.post("/targets", auth().requireScope("fleet:control"), (_req, res) => {
      res.json({ ran: true });
    });
    app.use(api);

    const response = await request(app).post("/targets");
    expect(response.status).toBe(401);
    expect((response.body as Record<string, unknown>).ran).toBeUndefined();
  });

  it("compares the method case-insensitively", async () => {
    // A framework hands the adapter whatever it parsed. `get` must not be a
    // mutation, and `post` must not become a safe method.
    const handler = auth().guard("none");

    for (const [method, expected] of [
      ["get", undefined],
      ["head", undefined],
      ["options", undefined],
      ["GET", undefined],
      ["post", 500],
      ["PoSt", 500],
      ["POST", 500],
    ] as const) {
      const res = fakeResponse();
      await runHandler(handler, { method }, res);
      expect(res.statusCode).toBe(expected);
    }
  });
});

describe("a guard that cannot do its job fails closed", () => {
  const guardedMutation = {
    method: "POST",
    authorization: "Bearer operator.token",
  };

  it("never runs the handler when the injected introspector rejects", async () => {
    // B2. A host may supply its own transport. If it rejects, the request
    // must not reach the handler: `.catch(() => next())` would run it with no
    // identity and no authorization at all.
    const app = express();
    const failing = createExpressAuth({
      introspect: () => Promise.reject(new Error("transport exploded")),
    });
    app.use(failing.guard("fleet:control"));
    app.post("/targets", (_req, res) => {
      res.json({ ran: true });
    });

    const response = await request(app)
      .post("/targets")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBeGreaterThanOrEqual(500);
    expect((response.body as Record<string, unknown>).ran).toBeUndefined();
    expect(response.text).not.toContain('"ran"');
  });

  it("never runs the handler when the injected introspector throws", async () => {
    const app = express();
    const throwing = createExpressAuth({
      introspect: () => {
        throw new Error("transport exploded synchronously");
      },
    });
    app.use(throwing.guard("fleet:control"));
    app.post("/targets", (_req, res) => {
      res.json({ ran: true });
    });

    const response = await request(app)
      .post("/targets")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBeGreaterThanOrEqual(500);
    expect((response.body as Record<string, unknown>).ran).toBeUndefined();
  });

  it("passes the error to next() rather than calling next() bare", async () => {
    const handler = createExpressAuth({
      introspect: () => Promise.reject(new Error("transport exploded")),
    }).guard("fleet:control");
    const res = fakeResponse();
    const { nexted, error } = await runHandler(handler, guardedMutation, res);
    expect(nexted).toBe(true);
    // Bare `next()` is the mutant: Express would then run the handler.
    expect(error).toBeInstanceOf(Error);
  });

  it("500s a POST whose resolver throws, without running the handler", async () => {
    // B3. A resolver that throws has told us nothing about this route.
    const app = express();
    app.use(
      auth().guard(() => {
        throw new Error("the route table is broken");
      })
    );
    app.post("/targets", (_req, res) => {
      res.json({ ran: true });
    });

    const response = await request(app)
      .post("/targets")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(500);
    expect(response.body).toEqual({
      error: { message: MESSAGES.undeclaredRoute },
    });
    expect((response.body as Record<string, unknown>).ran).toBeUndefined();
  });

  it("500s a throwing resolver on EVERY method, safe ones included", async () => {
    // The old fallback was `"none"`, which serves every safe method
    // anonymously the moment the route table throws; a `"session"` fallback
    // would serve them to anyone holding any token at all. Both are guesses
    // about a route nobody could describe. 500 on all of them.
    const handler = auth().guard(() => {
      throw new Error("the route table is broken");
    });

    for (const method of ["GET", "HEAD", "OPTIONS", "POST", "DELETE"]) {
      const res = fakeResponse();
      const { nexted } = await runHandler(handler, { method }, res);
      expect(nexted).toBe(false);
      expect(res.statusCode).toBe(500);
      expect(res.body).toEqual({ error: { message: MESSAGES.undeclaredRoute } });
    }
  });

  it("500s a throwing resolver even for a caller holding a good token", async () => {
    const handler = auth().guard(() => {
      throw new Error("the route table is broken");
    });
    const res = fakeResponse();
    await runHandler(
      handler,
      { method: "GET", authorization: "Bearer operator.token" },
      res
    );
    expect(res.statusCode).toBe(500);
  });
});

describe("the guard trusts req.method and nothing else", () => {
  it("ignores X-HTTP-Method-Override", async () => {
    // S7. No override is honoured here, and none ever will be: if one were, a
    // POST could present itself as a GET and walk past a mutation's scope. A
    // service that wants overrides mounts that middleware BEFORE the guard,
    // so the guard sees the method the request is actually handled as.
    const app = fleetApp();

    const asGet = await request(app)
      .post("/api/fleet/v1/ships/navigate")
      .set("X-HTTP-Method-Override", "GET");
    expect(asGet.status).toBe(401);

    const asHead = await request(app)
      .post("/api/fleet/v1/ships/navigate")
      .set("X-HTTP-Method-Override", "HEAD");
    expect(asHead.status).toBe(401);

    // And a public GET is not turned into a refused POST by the header
    // either: the override is simply not read.
    const stillAGet = await request(app)
      .get("/health")
      .set("X-HTTP-Method-Override", "POST");
    expect(stillAGet.status).toBe(200);
  });
});

describe("there is one source of truth for the identity", () => {
  it("publishes nothing under a string key, and no separate kind", async () => {
    // The identity lives under a module-private Symbol, so there is no
    // `res.locals.identity` to read instead of `identityOf(res)` — and none of
    // it appears in `Object.keys(res.locals)` or in a `JSON.stringify` of it.
    //
    // There is also deliberately no second copy of `kind`: a second copy of
    // the center's answer is a second thing to keep true, and the failure this
    // package exists to prevent is a service deriving `kind` for itself.
    const app = express();
    const api = secured(express.Router());
    api.get("/whoami", auth().requireSession(), (_req, res) => {
      res.json({
        locals: Object.keys(res.locals).sort(),
        serialised: JSON.stringify(res.locals),
        kindOf: kindOf(res),
        actorOf: actorOf(res),
      });
    });
    app.use(api);

    const response = await request(app)
      .get("/whoami")
      .set("Authorization", "Bearer disagreeing.token");
    expect(response.status).toBe(200);
    expect((response.body as Record<string, unknown>).locals).toEqual([]);
    expect((response.body as Record<string, unknown>).serialised).toBe("{}");
    // The center said machine for a `user_` subject, and that is what is read.
    expect((response.body as Record<string, unknown>).kindOf).toBe("machine");
    expect((response.body as Record<string, unknown>).actorOf).toBe("user_operator");
  });

  it("records what the route declared, and null when it declared nothing", async () => {
    const app = express();
    app.use(auth().guard(() => undefined));
    app.get("/x", (_req, res) => {
      res.json({ ran: true });
    });

    const response = await request(app).get("/x");
    expect(response.status).toBe(500);
    expect(response.body).toEqual({
      error: { message: MESSAGES.undeclaredRoute },
    });
  });
});

describe("passthrough()", () => {
  it("refuses a handler with no reason given", () => {
    expect(() => passthrough(corsish(), "")).toThrow(/reason/);
  });

  it("returns a delegating WRAPPER, preserving arity, and brands only that", () => {
    // The brand must not land on the caller's own function: a caller holding a
    // vouched-for function could register it anywhere, undeclared.
    const handler = corsish();
    const wrapped = passthrough(handler, "answers preflights");
    expect(wrapped).not.toBe(handler);
    // Arity is how Express tells an error handler from an ordinary one.
    expect(wrapped.length).toBe(handler.length);
    expect(wrapped.length).toBe(3);

    const api = secured(express.Router());
    expect(() => api.use(wrapped)).not.toThrow();
    expect(() => api.use(handler as never)).toThrow(/neither a declaration nor/);
  });

  it("preserves the arity of an error handler it is given", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars, @typescript-eslint/no-empty-function -- Express tells an error handler apart by arity (four parameters), so the unused ones must stay
    const onError = (_e: unknown, _req: Request, _res: Response, _n: NextFunction): void => {};
    expect(passthrough(onError, "logs errors; never answers").length).toBe(4);
  });

  it("delegates the call, with the same arguments", () => {
    const seen: unknown[] = [];
    const inner = (a: unknown, b: unknown, c: unknown): void => {
      seen.push(a, b, c);
    };
    passthrough(inner, "records")(1, 2, 3);
    expect(seen).toEqual([1, 2, 3]);
  });
});
