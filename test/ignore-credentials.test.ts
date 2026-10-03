/**
 * @file `ignoreCredentials()`: routes that never read identity.
 *
 * The claim is stronger than "public". `allowPublic()` still verifies a
 * bearer it is shown (the fixture's `inactive-token-on-public-get`), so an
 * expired token is a 401 and a down center a 503 on a public page. Health,
 * API docs and static files must not depend on auth-service at all, so this
 * declaration does not read the `Authorization` header and never calls the
 * center. What it gives up for that is every mutating method: refused at
 * registration, and a `500` before any header is read if one reaches it
 * through a `use()` mount.
 *
 * "Not read" is asserted, not inferred: every request passes a trap that
 * records any access to `authorization` on `req.headers`, through
 * `req.get` / `req.header`, on `req.headersDistinct`, and any read of the
 * credential's slot in `req.rawHeaders`; positive controls prove the trap
 * sees an `allowPublic()` route reading it and sees each of the side doors.
 */

import express, { type NextFunction, type Request, type Response } from "express";
import request from "supertest";

import type { CenterAnswer } from "../src/center";
import {
  actorOf,
  createExpressAuth,
  CREDENTIALS_IGNORED,
  hasScope,
  identityOf,
  kindOf,
  passthrough,
  requirementOf,
  secured,
} from "../src/express";
import { MESSAGES } from "../src/messages";
import { countFetches } from "./support/fixture";

const ACTIVE: CenterAnswer = {
  state: "active",
  identity: { sub: "user_operator", kind: "operator", scopes: ["fleet:control"] },
};

/** An auth whose center answers from a table, and counts what it was asked. */
const countingAuth = () => {
  const calls: string[] = [];
  const auth = createExpressAuth({
    introspect: (token: string) => {
      calls.push(token);
      return Promise.resolve(
        token === "operator.token" ? ACTIVE : ({ state: "inactive" } as const)
      );
    },
  });
  return { auth, calls };
};

/** Every access to the credential, however it was attempted. */
let reads: string[] = [];
let ran: string[] = [];
beforeEach(() => {
  reads = [];
  ran = [];
});

const isAuthorization = (key: PropertyKey): boolean =>
  typeof key === "string" && key.toLowerCase() === "authorization";

/** A Proxy over a header map that records every look at `authorization`. */
const recordingMap = <T extends object>(target: T, label: string): T =>
  new Proxy(target, {
    get(t, key, receiver) {
      if (isAuthorization(key)) reads.push(`${label}.get`);
      return Reflect.get(t, key, receiver);
    },
    has(t, key) {
      if (isAuthorization(key)) reads.push(`${label}.has`);
      return Reflect.has(t, key);
    },
    getOwnPropertyDescriptor(t, key) {
      if (isAuthorization(key)) reads.push(`${label}.descriptor`);
      return Reflect.getOwnPropertyDescriptor(t, key);
    },
  });

/**
 * Replaces `req.headers` and `req.headersDistinct` with recording Proxies,
 * `req.rawHeaders` with a Proxy that records any read of a value whose name
 * is `authorization`, and `req.get` / `req.header` with recording
 * wrappers. Mounted first, as a passthrough, so everything after it — the
 * declaration included — sees only the trapped request.
 */
const trap = passthrough((req: Request, _res: Response, next: NextFunction): void => {
  // Read before `rawHeaders` is replaced: Node builds it lazily FROM
  // `rawHeaders`, and the trap must not record its own setup.
  const distinct = req.headersDistinct as Record<string, unknown>;
  Object.defineProperty(req, "headersDistinct", {
    configurable: true,
    enumerable: true,
    value: recordingMap(distinct, "headersDistinct"),
  });
  const raw = req.rawHeaders;
  req.rawHeaders = new Proxy(raw, {
    get(target, key, receiver) {
      // [name, value, name, value, …]: the credential is the odd slot after
      // an `authorization` name. Reading names is not reading the credential.
      if (typeof key === "string" && /^\d+$/.test(key)) {
        const index = Number(key);
        if (index % 2 === 1 && isAuthorization(target[index - 1] ?? "")) {
          reads.push("rawHeaders.value");
        }
      }
      return Reflect.get(target, key, receiver) as unknown;
    },
  });
  req.headers = recordingMap(req.headers, "headers");
  // eslint-disable-next-line @typescript-eslint/unbound-method -- always invoked with an explicit this via original.call(this, name)
  const original = req.get as (name: string) => unknown;
  req.get = req.header = function (this: unknown, name: string): unknown {
    if (isAuthorization(name)) reads.push("req.get");
    return original.call(this, name);
  } as Request["get"];
  next();
}, "test trap: records credential reads; never answers");

/** A handler that reports everything the accessors say. */
const report =
  (name = "handler") =>
  (_req: unknown, res: Response): void => {
    ran.push(name);
    res.json({
      identity: identityOf(res),
      actor: actorOf(res),
      kind: kindOf(res),
      hasScope: hasScope(res, "fleet:control"),
      requirement: requirementOf(res),
    });
  };

const BEARERS: readonly [string, string][] = [
  ["a valid", "Bearer operator.token"],
  ["an inactive", "Bearer expired.token"],
  ["a garbage", "Bearer %%%not-a-token%%%"],
];

const VISITOR = {
  identity: null,
  actor: null,
  kind: null,
  hasScope: false,
  requirement: CREDENTIALS_IGNORED,
};

// ---------------------------------------------------------------------------
// The header is never read and the center never called
// ---------------------------------------------------------------------------

describe("ignoreCredentials() on a GET route", () => {
  const build = () => {
    const { auth, calls } = countingAuth();
    const app = secured(express());
    app.use(trap);
    app.get("/health", auth.ignoreCredentials(), report());
    app.get("/public", auth.allowPublic(), report("public"));
    return { app, calls };
  };

  it("serves a caller with no header, as a visitor", async () => {
    const { app, calls } = build();
    const response = await request(app).get("/health");
    expect(response.status).toBe(200);
    expect(response.body).toEqual(VISITOR);
    expect(calls).toEqual([]);
    expect(reads).toEqual([]);
  });

  it.each(BEARERS)(
    "serves %s bearer 200 without reading it or asking the center",
    async (_label, authorization) => {
      const { app, calls } = build();
      const response = await request(app)
        .get("/health")
        .set("Authorization", authorization);
      expect(response.status).toBe(200);
      expect(response.body).toEqual(VISITOR);
      expect(calls).toEqual([]);
      expect(reads).toEqual([]);
      expect(ran).toEqual(["handler"]);
    }
  );

  it("POSITIVE CONTROL: the trap sees allowPublic() read the header", async () => {
    // Without this the assertions above could pass against a trap that
    // records nothing.
    const { app, calls } = build();
    const response = await request(app)
      .get("/public")
      .set("Authorization", "Bearer expired.token");
    expect(response.status).toBe(401);
    expect(reads.length).toBeGreaterThan(0);
    expect(calls).toEqual(["expired.token"]);
  });

  it.each([
    [
      "rawHeaders",
      "rawHeaders.value",
      (req: Request): unknown => {
        const raw = req.rawHeaders;
        const at = raw.findIndex((v, i) => i % 2 === 0 && v.toLowerCase() === "authorization");
        return raw[at + 1];
      },
    ],
    ["rawHeaders, iterated", "rawHeaders.value", (req: Request): unknown => [...req.rawHeaders].join(",")],
    ["headersDistinct", "headersDistinct.get", (req: Request): unknown => req.headersDistinct.authorization],
    ["headersDistinct, spread", "headersDistinct.descriptor", (req: Request): unknown => ({ ...req.headersDistinct })],
  ])(
    "POSITIVE CONTROL: the trap sees a read through %s",
    async (_label, recorded, read) => {
      // Without these, a mutant reading the credential through a side door
      // of IncomingMessage would pass the assertions above unseen.
      const { auth } = countingAuth();
      const app = secured(express());
      app.use(trap);
      app.get("/leak", auth.ignoreCredentials(), (req, res) => {
        res.json({ leaked: read(req) !== undefined });
      });
      const response = await request(app)
        .get("/leak")
        .set("Authorization", "Bearer operator.token");
      expect(response.status).toBe(200);
      expect(reads).toContain(recorded);
    }
  );

  it("stays up while the center is down, where allowPublic() answers 503", async () => {
    // A real config pointing at a port nothing listens on, and a spy on the
    // global fetch, so a call the injected counter could not see is counted.
    const auth = createExpressAuth({
      url: "http://127.0.0.1:9/auth/v1/introspect",
      secret: "ignore-credentials-suite",
    });
    const app = secured(express());
    app.use(trap);
    app.get("/health", auth.ignoreCredentials(), report());
    app.get("/public", auth.allowPublic(), report("public"));

    const fetches = countFetches();
    try {
      const ignored = await request(app)
        .get("/health")
        .set("Authorization", "Bearer operator.token");
      expect(ignored.status).toBe(200);
      expect(fetches.calls).toBe(0);
      expect(reads).toEqual([]);

      const optional = await request(app)
        .get("/public")
        .set("Authorization", "Bearer operator.token");
      expect(optional.status).toBe(503);
      expect(fetches.calls).toBe(1);
    } finally {
      fetches.restore();
    }
  });

  it("hands the handler no identity even behind a guard that verified one", async () => {
    const { auth, calls } = countingAuth();
    const app = secured(express());
    app.use(auth.guard("session"));
    app.get("/health", auth.ignoreCredentials(), report());

    const response = await request(app)
      .get("/health")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(200);
    expect(response.body).toEqual(VISITOR);
    // The outer guard asked, once; the route itself added nothing.
    expect(calls).toEqual(["operator.token"]);
  });

  it("serves HEAD through the GET route, unread", async () => {
    const { app, calls } = build();
    const response = await request(app)
      .head("/health")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(200);
    expect(calls).toEqual([]);
    expect(reads).toEqual([]);
  });

  it("serves head() and options() registrations too", async () => {
    const { auth, calls } = countingAuth();
    const app = secured(express());
    app.use(trap);
    app.head("/h", auth.ignoreCredentials(), (_req, res) => {
      res.status(204).end();
    });
    app.options("/o", auth.ignoreCredentials(), (_req, res) => {
      res.status(204).end();
    });

    const head = await request(app).head("/h").set("Authorization", "Bearer x");
    const options = await request(app)
      .options("/o")
      .set("Authorization", "Bearer x");
    expect(head.status).toBe(204);
    expect(options.status).toBe(204);
    expect(calls).toEqual([]);
    expect(reads).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Mutating methods
// ---------------------------------------------------------------------------

describe("ignoreCredentials() is refused on a mutating registration", () => {
  const noop = (_req: unknown, res: Response): void => {
    ran.push("mutation");
    res.json({ ran: true });
  };

  it.each(["post", "put", "patch", "delete", "all", "trace", "propfind"])(
    "refuses app.%s(...)",
    (method) => {
      const { auth } = countingAuth();
      const app = secured(express()) as unknown as Record<
        string,
        (...args: unknown[]) => unknown
      >;
      expect(() => app[method]?.("/x", auth.ignoreCredentials(), noop)).toThrow(
        /accepted only on get, head and options routes and on\s+use\(\) mounts/
      );
    }
  );

  it.each(["post", "all"])("refuses route(...).%s(...)", (method) => {
    const { auth } = countingAuth();
    const router = secured(express.Router());
    const route = router.route("/x") as unknown as Record<
      string,
      (...args: unknown[]) => unknown
    >;
    expect(() => route[method]?.(auth.ignoreCredentials(), noop)).toThrow(
      /ignoreCredentials\(\)/
    );
  });

  it("refuses it behind a passthrough, and in a nested array", () => {
    const { auth } = countingAuth();
    const app = secured(express());
    const parse = passthrough(express.json(), "parses bodies; never answers");
    expect(() =>
      app.post("/x", parse as never, auth.ignoreCredentials(), noop)
    ).toThrow(/ignoreCredentials\(\)/);
    expect(() =>
      app.post("/y", [[auth.ignoreCredentials()], noop] as never)
    ).toThrow(/ignoreCredentials\(\)/);
  });

  it("does not register the refused route", async () => {
    const { auth } = countingAuth();
    const app = secured(express());
    expect(() => app.post("/x", auth.ignoreCredentials(), noop)).toThrow();
    const response = await request(app).post("/x");
    expect(response.status).toBe(404);
    expect(ran).toEqual([]);
  });

  it("accepts get, head, options and a route().get chain", () => {
    const { auth } = countingAuth();
    const app = secured(express());
    expect(() => app.get("/a", auth.ignoreCredentials(), noop)).not.toThrow();
    expect(() => app.head("/b", auth.ignoreCredentials(), noop)).not.toThrow();
    expect(() => app.options("/c", auth.ignoreCredentials(), noop)).not.toThrow();
    expect(() =>
      app.route("/d").get(auth.ignoreCredentials(), noop)
    ).not.toThrow();
  });

  it("leaves a chain's own mutating method to its own declaration", async () => {
    const { auth, calls } = countingAuth();
    const app = secured(express());
    app.use(trap);
    app
      .route("/r")
      .get(auth.ignoreCredentials(), report())
      .post(auth.requireScope("fleet:control"), report("post"));

    const anonymous = await request(app).post("/r");
    expect(anonymous.status).toBe(401);
    expect(ran).toEqual([]);

    const authorized = await request(app)
      .post("/r")
      .set("Authorization", "Bearer operator.token");
    expect(authorized.status).toBe(200);
    expect(calls).toEqual(["operator.token"]);
  });
});

describe("a mutating request that reaches it through a use() mount", () => {
  const build = () => {
    const { auth, calls } = countingAuth();
    const app = secured(express());
    app.use(trap);
    app.use("/assets", auth.ignoreCredentials(), (req, res) => {
      ran.push(req.method);
      res.json({ served: true });
    });
    return { app, calls };
  };

  it("serves GET under the mount", async () => {
    const { app, calls } = build();
    const response = await request(app)
      .get("/assets/app.js")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(200);
    expect(calls).toEqual([]);
    expect(reads).toEqual([]);
  });

  it.each(["post", "put", "patch", "delete"] as const)(
    "answers %s 500 before reading any header",
    async (method) => {
      const { app, calls } = build();
      const response = await request(app)
        [method]("/assets/app.js")
        .set("Authorization", "Bearer operator.token");
      expect(response.status).toBe(500);
      expect(response.body).toEqual({
        error: { message: MESSAGES.undeclaredRoute },
      });
      expect(reads).toEqual([]);
      expect(calls).toEqual([]);
      expect(ran).toEqual([]);
    }
  );

  it("hands no identity on the 500 either, even behind a guard that verified one", async () => {
    const { auth, calls } = countingAuth();
    const app = secured(express());
    let seen: unknown = "unset";
    app.use(
      passthrough((_req: Request, res: Response, next: NextFunction) => {
        res.on("finish", () => {
          seen = identityOf(res);
        });
        next();
      }, "test probe; never answers")
    );
    app.use(auth.guard("session"));
    app.use("/assets", auth.ignoreCredentials(), report());
    const response = await request(app)
      .post("/assets/x")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(500);
    // The outer guard verified the operator; the mount still hands out none.
    expect(calls).toEqual(["operator.token"]);
    expect(seen).toBeNull();
  });

  it("reports the requirement on the 500 too", async () => {
    const { auth } = countingAuth();
    const app = secured(express());
    let seen: unknown = "unset";
    app.use(
      passthrough((_req: Request, res: Response, next: NextFunction) => {
        res.on("finish", () => {
          seen = requirementOf(res);
        });
        next();
      }, "test probe; never answers")
    );
    app.use("/assets", auth.ignoreCredentials(), report());
    const response = await request(app).post("/assets/x");
    expect(response.status).toBe(500);
    expect(seen).toBe(CREDENTIALS_IGNORED);
  });
});

// ---------------------------------------------------------------------------
// The declaration rules
// ---------------------------------------------------------------------------

describe("ignoreCredentials() obeys the declaration rules", () => {
  const h = (_req: unknown, res: Response): void => {
    res.json({});
  };

  it("works as a declared mount ahead of third-party middleware", async () => {
    const { auth, calls } = countingAuth();
    const app = secured(express());
    app.use(trap);
    const serve = [
      (_req: Request, _res: Response, next: NextFunction) => { next(); },
      (_req: Request, _res: Response, next: NextFunction) => { next(); },
    ];
    app.use("/api/fleet/swagger", auth.ignoreCredentials(), serve, report());

    const response = await request(app)
      .get("/api/fleet/swagger/index.html")
      .set("Authorization", "Bearer expired.token");
    expect(response.status).toBe(200);
    expect(response.body).toEqual(VISITOR);
    expect(calls).toEqual([]);
    expect(reads).toEqual([]);
  });

  it("is refused after a handler, on a route and on a mount", () => {
    const { auth } = countingAuth();
    const app = secured(express());
    expect(() => app.get("/x", h as never, auth.ignoreCredentials())).toThrow(
      /before its authorization declaration/
    );
    expect(() => app.use("/y", h as never, auth.ignoreCredentials())).toThrow(
      /before its authorization declaration/
    );
  });

  it.each([
    ["allowPublic()", (a: ReturnType<typeof createExpressAuth>) => a.allowPublic()],
    ["requireSession()", (a: ReturnType<typeof createExpressAuth>) => a.requireSession()],
    ["guard()", (a: ReturnType<typeof createExpressAuth>) => a.guard("session")],
    ["a second ignoreCredentials()", (a: ReturnType<typeof createExpressAuth>) => a.ignoreCredentials()],
  ])("is refused alongside %s", (_label, second) => {
    const { auth } = countingAuth();
    const app = secured(express());
    expect(() =>
      app.get("/x", auth.ignoreCredentials(), second(auth), h)
    ).toThrow(/more than one authorization declaration/);
    expect(() =>
      app.get("/y", second(auth), auth.ignoreCredentials(), h)
    ).toThrow(/more than one authorization declaration/);
    expect(() =>
      app.use("/z", auth.ignoreCredentials(), second(auth), h)
    ).toThrow(/more than one authorization declaration/);
  });

  it("names the mutation rule, not the double declaration, on a mutating route carrying both", () => {
    // `post("/x", requireSession(), ignore, h)` breaks two rules. The fix is
    // to drop ignoreCredentials(), so that is the rule the message names.
    const { auth } = countingAuth();
    const app = secured(express());
    let message = "";
    try {
      app.post("/x", auth.requireSession(), auth.ignoreCredentials(), h);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/^app\.post\(\/x\) was registered with ignoreCredentials\(\)\./);
    expect(message).toMatch(/accepted only on get, head and options routes/);
    expect(message).not.toMatch(/more than one authorization declaration/);
  });

  it("is refused as a second declaration on a route() chain", () => {
    const { auth } = countingAuth();
    const app = secured(express());
    const route = app.route("/x").get(auth.ignoreCredentials(), h);
    expect(() => route.get(auth.requireSession(), h)).toThrow(
      /more than one authorization declaration/
    );
  });

  it("cannot be forged", () => {
    // The brand lives in module-private WeakSets. A function that merely
    // looks like the declaration is an undeclared handler.
    function ignoreCredentials(_req: unknown, _res: unknown, next: () => void): void {
      next();
    }
    const forged = Object.assign(ignoreCredentials, {
      ignoresCredentials: true,
      requires: CREDENTIALS_IGNORED,
    });
    const app = secured(express());
    expect(() => app.get("/x", forged as never, h)).toThrow(
      /without an authorization declaration/
    );
    expect(() => app.use("/y", forged as never, h)).toThrow(
      /neither a declaration nor a vouched-for middleware/
    );
  });

  it("names itself in the how-to-declare message", () => {
    const app = secured(express());
    expect(() => app.get("/x", h)).toThrow(/auth\.ignoreCredentials\(\)/);
  });
});

describe("the reported word is reserved", () => {
  it("requireScope() refuses it", () => {
    const { auth } = countingAuth();
    expect(() => auth.requireScope(CREDENTIALS_IGNORED)).toThrow(/reserved/);
    expect(() => auth.requireScope(CREDENTIALS_IGNORED)).toThrow(
      /ignoreCredentials/
    );
  });

  it("a fixed guard() refuses it", () => {
    const { auth } = countingAuth();
    expect(() => auth.guard(CREDENTIALS_IGNORED)).toThrow(/reserved/);
  });

  it("a resolver returning it is undeclared: 500, center not called", async () => {
    // Resolver vocabulary is unchanged. The word is not a way to reach
    // ignoreCredentials() from a guard, nor a scope literal.
    const { auth, calls } = countingAuth();
    const app = express();
    app.use(auth.guard(() => CREDENTIALS_IGNORED));
    app.get("/x", report());
    const response = await request(app)
      .get("/x")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(500);
    expect(response.body).toEqual({ error: { message: MESSAGES.undeclaredRoute } });
    expect(calls).toEqual([]);
    expect(ran).toEqual([]);
  });
});

