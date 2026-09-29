/**
 * @file What `secured()` accepts at registration, and why each rule exists.
 *
 * The third review found that "a declaration is present somewhere in the
 * argument list" is not a rule at all: Express runs a route's handlers in
 * registration order, so `api.get("/x", handler, requireScope("y"))` served
 * `/x` to anyone with no credential and no call to the center, and registered
 * without complaint. The rule is therefore **positional** — the declaration is
 * the first handler — and it is enforced here for every ordering, for
 * `route()` chains, and for `use()`.
 *
 * The second finding was the opposite failure: `use()` demanded that every
 * item be individually branded, which refused four constructs the three
 * consumers actually contain. A `use()` is now a **declared mount**: a leading
 * declaration covers the rest of the list. All five constructs are registered
 * and driven below.
 *
 * No HTTP center here: an injected introspector is both faster and able to
 * count calls, which is half of what these tests assert.
 */

import { METHODS } from "node:http";

import express, { type Express } from "express";
import request from "supertest";

import type { CenterAnswer } from "../src/center";
import {
  createExpressAuth,
  notFound,
  passthrough,
  secured,
} from "../src/express";
import { MESSAGES } from "../src/messages";

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

const auth = () => countingAuth().auth;

/** A handler that records that it ran. A side effect nobody authorized is the bug. */
let ran: string[] = [];
beforeEach(() => {
  ran = [];
});
const handler =
  (name = "handler") =>
  (_req: unknown, res: any): void => {
    ran.push(name);
    res.json({ ran: name });
  };

// ---------------------------------------------------------------------------
// B1. The declaration is the FIRST handler
// ---------------------------------------------------------------------------

describe("B1. a route's declaration must come first", () => {
  it("accepts a declaration in first position", () => {
    const api = secured(express.Router());
    expect(() =>
      api.get("/a", auth().requireSession(), handler())
    ).not.toThrow();
  });

  it("refuses a declaration AFTER the handler", () => {
    // The bypass exactly as the review wrote it. Registering this used to
    // succeed, and `GET /after` then answered 200 with no credential and zero
    // calls to the center, because the handler ran first and answered.
    const api = secured(express.Router());
    expect(() =>
      api.get("/after", handler() as never, auth().requireScope("x"))
    ).toThrow(/before its authorization declaration/);
  });

  it("refuses a handler before a declaration in the middle of the list", () => {
    const api = secured(express.Router());
    expect(() =>
      api.get(
        "/middle",
        handler("first") as never,
        auth().requireScope("x"),
        handler("last") as never
      )
    ).toThrow(/before its authorization declaration/);
  });

  it("refuses a route with no declaration at all", () => {
    const api = secured(express.Router());
    expect(() => api.get("/none", handler())).toThrow(
      /without an authorization declaration/
    );
  });

  it("names the route and says how to fix it", () => {
    const api = secured(express.Router());
    expect(() => api.get("/ships/:id", handler())).toThrow(/\/ships\/:id/);
    expect(() => api.get("/ships/:id", handler())).toThrow(/allowPublic/);
    expect(() => api.get("/ships/:id", handler())).toThrow(/requireScope/);
    expect(() =>
      api.get("/ships/:id", handler() as never, auth().allowPublic())
    ).toThrow(/\/ships\/:id/);
  });

  it("allows a vouched-for passthrough, and only that, ahead of the declaration", () => {
    const api = secured(express.Router());
    const parse = passthrough(express.json(), "parses bodies; never answers");
    const log = passthrough(
      (_req: any, _res: any, next: any) => next(),
      "logs; never answers"
    );
    expect(() =>
      api.post("/a", parse as never, log as never, auth().requireSession(), handler())
    ).not.toThrow();

    // The same middleware without the vouching is refused: `secured()` cannot
    // tell a logger from a route, and the whole point is that it must not guess.
    const unvouched = (_req: any, _res: any, next: any): void => next();
    expect(() =>
      api.post("/b", unvouched as never, auth().requireSession(), handler())
    ).toThrow(/before its authorization declaration/);
  });

  it("applies the rule through nested arrays, which Express flattens", () => {
    const api = secured(express.Router());
    expect(() =>
      api.get("/a", [auth().requireSession(), handler()] as never)
    ).not.toThrow();
    expect(() =>
      api.get("/b", [handler(), auth().requireSession()] as never)
    ).toThrow(/before its authorization declaration/);
    expect(() =>
      api.get("/c", [[auth().requireSession()], handler()] as never)
    ).not.toThrow();
  });

  it("accepts a guard() in first position, which declares for the route too", () => {
    const api = secured(express.Router());
    expect(() =>
      api.get("/a", auth().guard(() => "session"), handler())
    ).not.toThrow();
  });

  it("cannot be fooled by a forged brand", () => {
    // The brands live in module-private WeakMaps, so there is no property for
    // a caller to set. A handler that claims to be a declaration is not one.
    const forged = Object.assign(handler(), { __declares: "fleet:control" });
    const api = secured(express.Router());
    expect(() => api.get("/forged", forged as never)).toThrow(
      /without an authorization declaration/
    );
  });

  it("refuses the whole registration rather than registering the route", async () => {
    // The throw must happen BEFORE Express is called, or a refused route is
    // still served. Proven by asking for it afterwards.
    const app = express();
    const api = secured(express.Router());
    expect(() => api.get("/after", handler() as never, auth().requireScope("x"))).toThrow();
    app.use(api);

    const response = await request(app).get("/after");
    expect(response.status).toBe(404);
    expect(ran).toEqual([]);
  });
});

describe("B1. exactly one declaration per route", () => {
  it("refuses two declarations on one registration", () => {
    // Two declarations are two center calls for one request and two answers to
    // reconcile. Refused outright rather than given a precedence rule.
    const api = secured(express.Router());
    const a = auth();
    expect(() =>
      api.get("/two", a.requireSession(), a.requireScope("fleet:control"), handler())
    ).toThrow(/more than one authorization declaration/);
  });

  it("refuses a declaration plus a guard on the same route", () => {
    const api = secured(express.Router());
    const a = auth();
    expect(() =>
      api.get("/two", a.guard(() => "session"), a.requireScope("fleet:control"), handler())
    ).toThrow(/more than one authorization declaration/);
  });

  it("refuses an allowPublic() that would override a requireScope()", () => {
    // The mutation this kills: `allowPublic` winning over `requireScope` and
    // quietly publishing a controlled route.
    const api = secured(express.Router());
    const a = auth();
    expect(() =>
      api.post("/x", a.requireScope("fleet:control"), a.allowPublic(), handler())
    ).toThrow(/more than one authorization declaration/);
    expect(() =>
      api.post("/y", a.allowPublic(), a.requireScope("fleet:control"), handler())
    ).toThrow(/more than one authorization declaration/);
  });
});

describe("B1. the same rule inside route()", () => {
  it("refuses an undeclared method on a route() chain", () => {
    const api = secured(express.Router());
    expect(() => api.route("/x").get(handler())).toThrow(
      /without an authorization declaration/
    );
  });

  it("refuses a declaration after the handler on a route() chain", () => {
    const api = secured(express.Router());
    expect(() =>
      api.route("/x").get(handler() as never, auth().requireSession())
    ).toThrow(/before its authorization declaration/);
  });

  it("accepts a declared first handler, and further handlers after it", () => {
    const api = secured(express.Router());
    const route = api.route("/x");
    expect(() => route.get(auth().requireSession(), handler("one"))).not.toThrow();
    // The method already carries a declaration, so a later `.get(more)` on the
    // same chain is behind it and needs none of its own.
    expect(() => route.get(handler("two"))).not.toThrow();
  });

  it("refuses a second declaration added later on the same chain", () => {
    const api = secured(express.Router());
    const route = api.route("/x");
    route.get(auth().requireSession(), handler());
    expect(() => route.get(auth().requireScope("fleet:control"))).toThrow(
      /more than one authorization declaration/
    );
  });

  it("tracks declarations per method, and lets all() cover every method", () => {
    const api = secured(express.Router());
    const perMethod = api.route("/x");
    perMethod.get(auth().requireSession(), handler());
    // A declaration on GET says nothing about POST.
    expect(() => perMethod.post(handler())).toThrow(
      /without an authorization declaration/
    );

    const covered = api.route("/y");
    covered.all(auth().requireSession(), handler());
    expect(() => covered.post(handler())).not.toThrow();
  });

  it("enforces it through a real request", async () => {
    const app = express();
    const api = secured(express.Router());
    api.route("/ships").get(auth().requireScope("fleet:control"), handler("list"));
    app.use(api);

    const denied = await request(app).get("/ships");
    expect(denied.status).toBe(401);
    expect(ran).toEqual([]);

    const allowed = await request(app)
      .get("/ships")
      .set("Authorization", "Bearer operator.token");
    expect(allowed.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// B2. use() is a declared mount
// ---------------------------------------------------------------------------

describe("B2. use() accepts the constructs the three consumers have", () => {
  const a = () => auth();

  it("1. st-gateway's proxy mount: a declaration, a parser and a handler", () => {
    const app = secured(express());
    expect(() =>
      app.use(
        "/proxy",
        a().requireSession(),
        express.raw({ type: "*/*", limit: "5mb" }),
        handler("proxy")
      )
    ).not.toThrow();
  });

  it("2. fleet's arity-2 JSON 404 catch-all, spelled notFound()", () => {
    const app = secured(express());
    expect(() =>
      app.use(
        notFound((_req: any, res: any) =>
          res.status(404).json({ error: { message: "not found" } })
        )
      )
    ).not.toThrow();
  });

  it("3. swagger-ui: a serve array and a setup handler behind one declaration", () => {
    // `swaggerUi.serve` is an ARRAY of middleware and `setup()` returns one
    // handler; both are third-party and neither can be branded.
    const app = secured(express());
    const serve = [
      (_req: any, _res: any, next: any) => next(),
      (_req: any, _res: any, next: any) => next(),
    ];
    const setup = (_req: any, res: any) => res.send("<html/>");
    expect(() =>
      app.use("/swagger", a().allowPublic(), serve as never, setup as never)
    ).not.toThrow();
  });

  it("4. express.static behind a declaration", () => {
    const app = secured(express());
    expect(() =>
      app.use("/assets", a().allowPublic(), express.static(__dirname))
    ).not.toThrow();
  });

  it("5. an error handler, which Express only ever calls with an error in hand", () => {
    const app = secured(express());
    const onError = (err: unknown, _req: any, res: any, _next: any): void => {
      res.status(500).json({ error: { message: String(err) } });
    };
    expect(() => app.use(onError as never)).not.toThrow();
  });

  it("and fleet's generated router: a guard, then the generated routes", () => {
    const app = secured(express());
    const generated = express.Router();
    expect(() =>
      app.use(
        "/api/fleet/v1",
        a().guard(({ method }) => (method === "GET" ? "session" : "fleet:control")),
        generated
      )
    ).not.toThrow();
  });

  it("still accepts a passthrough, a nested secured router and a bare guard", () => {
    const api = secured(express.Router());
    expect(() =>
      api.use(passthrough(express.json(), "parses bodies; never answers"))
    ).not.toThrow();
    expect(() => api.use(a().guard(() => "session"))).not.toThrow();
    expect(() => api.use("/nested", secured(express.Router()))).not.toThrow();
  });
});

describe("B2. a declared mount still has to put the declaration first", () => {
  it("refuses an unbranded handler ahead of the declaration", () => {
    const app = secured(express());
    expect(() =>
      app.use(
        "/proxy",
        express.raw({ type: "*/*" }) as never,
        auth().requireSession(),
        handler("proxy")
      )
    ).toThrow(/before its authorization declaration/);
  });

  it("refuses two declarations on one mount", () => {
    const app = secured(express());
    const a = auth();
    expect(() =>
      app.use("/proxy", a.allowPublic(), a.requireSession(), handler())
    ).toThrow(/more than one authorization declaration/);
  });

  it("refuses a mount with no declaration and nothing vouched for", () => {
    const api = secured(express.Router());
    expect(() => api.use(handler())).toThrow(/neither a declaration nor/);
    expect(() => api.use(handler())).toThrow(/passthrough/);
    expect(() => api.use(handler())).toThrow(/notFound/);
  });

  it("covers everything after the declaration, at runtime", async () => {
    // The mount's declaration governs the handler that answers, so an
    // unauthenticated caller never reaches it.
    const app = express();
    const secure = secured(express.Router());
    secure.use(
      "/proxy",
      auth().requireSession(),
      express.raw({ type: "*/*" }),
      handler("proxy")
    );
    app.use(secure);

    const denied = await request(app).post("/proxy/ships").send("raw-bytes");
    expect(denied.status).toBe(401);
    expect(denied.body).toEqual({ error: { message: MESSAGES.missingToken } });
    expect(ran).toEqual([]);

    const allowed = await request(app)
      .post("/proxy/ships")
      .set("Authorization", "Bearer operator.token")
      .send("raw-bytes");
    expect(allowed.status).toBe(200);
    expect(ran).toEqual(["proxy"]);
  });
});

describe("B2. notFound() is terminal", () => {
  const terminal = () =>
    notFound((_req: any, res: any) => {
      ran.push("notFound");
      res.status(404).json({ error: { message: "not found" } });
    });

  it("answers without a credential and without asking the center", async () => {
    // It serves no resource, so there is nothing to authorize — and a 404 that
    // introspected first would put the center on the path of every mistyped
    // URL and tell an anonymous caller which paths exist.
    const { auth: counting, calls } = countingAuth();
    const app = express();
    const api = secured(express.Router());
    api.get("/known", counting.requireSession(), handler("known"));
    api.use(terminal());
    app.use(api);

    const response = await request(app).get("/unknown");
    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: { message: "not found" } });
    expect(calls).toEqual([]);
  });

  it("refuses anything registered after it except an error handler", () => {
    const api = secured(express.Router());
    api.use(terminal());

    const onError = (_e: unknown, _req: any, res: any, _n: any): void => {
      res.status(500).end();
    };
    expect(() => api.use(onError as never)).not.toThrow();

    expect(() => api.get("/late", auth().allowPublic(), handler())).toThrow(
      /after a notFound\(\) handler/
    );
    expect(() =>
      api.use(passthrough(express.json(), "parses bodies; never answers"))
    ).toThrow(/after a notFound\(\) handler/);
  });

  it("refuses handlers after it within the same use() call", () => {
    const api = secured(express.Router());
    expect(() => api.use(terminal(), handler() as never)).toThrow(
      /notFound\(\) handler with handlers after it/
    );
  });

  it("is not accepted as a route's declaration", () => {
    // It is a brand meaning "serves no resource", not a decision about one.
    const api = secured(express.Router());
    expect(() => api.get("/x", terminal() as never)).toThrow(
      /without an authorization declaration/
    );
  });
});

// ---------------------------------------------------------------------------
// S2. The reserved words are not scopes
// ---------------------------------------------------------------------------

describe("S2. requireScope() refuses the reserved words", () => {
  it.each(["none", "session"])("throws for requireScope(%p)", (reserved) => {
    // Spelled as a scope, each read as a demand and silently produced its
    // opposite: `requireScope("none")` published the route, and
    // `requireScope("session")` downgraded it to any token at all.
    expect(() => auth().requireScope(reserved)).toThrow(/reserved/);
    expect(() => auth().requireScope(reserved)).toThrow(
      reserved === "none" ? /allowPublic/ : /requireSession/
    );
  });

  it.each(["", " ", "\t\n"])("throws for a blank scope (%j)", (blank) => {
    expect(() => auth().requireScope(blank)).toThrow(/scope literal/);
  });

  it("accepts a real scope", () => {
    expect(() => auth().requireScope("fleet:control")).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// S3. One request, at most one call to the center
// ---------------------------------------------------------------------------

describe("S3. one inbound request asks the center at most once", () => {
  /** A guard on the router and a declaration on the route: both enforce. */
  const app = (): { app: Express; calls: string[] } => {
    const { auth: counting, calls } = countingAuth();
    const application = express();
    const api = secured(express.Router());
    api.use(counting.guard(() => "session"));
    api.get("/ships", counting.requireScope("fleet:control"), handler("list"));
    api.get("/cargo", counting.requireSession(), handler("cargo"));
    application.use("/api", api);
    return { app: application, calls };
  };

  it("makes one call when a guard and a declaration both run", async () => {
    const { app: application, calls } = app();
    const response = await request(application)
      .get("/api/ships")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(200);
    expect(calls).toEqual(["operator.token"]);
  });

  it("still enforces the route's scope under a session guard", async () => {
    // Memoizing the ANSWER must not memoize the DECISION: each enforcement
    // point still compares the answer against its own requirement, so the
    // stricter effectively wins.
    const { auth: counting, calls } = countingAuth();
    const application = express();
    const api = secured(express.Router());
    api.use(counting.guard(() => "session"));
    api.get("/ships", counting.requireScope("universe:refresh"), handler("list"));
    application.use("/api", api);

    const response = await request(application)
      .get("/api/ships")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: { message: MESSAGES.missingScope } });
    expect(ran).toEqual([]);
    expect(calls).toEqual(["operator.token"]);
  });

  it("does not share the answer between requests", async () => {
    // The memo lives on `res.locals`, so it dies with the response. A
    // process-wide cache keyed on the header would hand one caller's identity
    // to the next caller presenting the same value, and would make revocation
    // mean nothing for its lifetime.
    const { app: application, calls } = app();
    for (let i = 0; i < 3; i += 1) {
      const response = await request(application)
        .get("/api/cargo")
        .set("Authorization", "Bearer operator.token");
      expect(response.status).toBe(200);
    }
    expect(calls).toEqual([
      "operator.token",
      "operator.token",
      "operator.token",
    ]);
  });

  it("asks again when the second enforcement point sees a different header", async () => {
    // The memo is keyed on the exact header value, not merely on "this
    // request". A key that ignored the header would answer the second
    // question about the first question's credential.
    const { auth: counting, calls } = countingAuth();
    const application = express();
    application.use(
      passthrough((_req: any, _res: any, next: any) => next(), "does nothing")
    );
    const api = express.Router();
    api.use(counting.guard(() => "session"));
    // A middleware that rewrites the credential between the two enforcement
    // points. Contrived, and precisely what the key exists to survive.
    api.use((req: any, _res: any, next: any) => {
      // The adapter reads the credential from rawHeaders (a rewrite of
      // req.headers or req.header() is ignored), so that is what changes.
      const kept: string[] = [];
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        if (String(req.rawHeaders[i]).toLowerCase() === "authorization") continue;
        kept.push(req.rawHeaders[i], req.rawHeaders[i + 1]);
      }
      req.rawHeaders = [...kept, "Authorization", "Bearer second.token"];
      next();
    });
    api.get("/ships", counting.requireSession(), handler("list"));
    application.use("/api", api);

    const response = await request(application)
      .get("/api/ships")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(401);
    expect(calls).toEqual(["operator.token", "second.token"]);
  });
});

// ---------------------------------------------------------------------------
// B3. No alias reaches the unpatched methods
// ---------------------------------------------------------------------------

/**
 * Express 4's `app.del` is `deprecate.function(app.delete)`: a wrapper around
 * the ORIGINAL delete, captured when Express loaded. Patching `app.delete`
 * never touched it, so 1.0.0 registered `secured(app).del("/d", h)` without a
 * declaration and served the DELETE.
 */
describe("B3. no alias reaches the unpatched route methods", () => {
  type Loose = Record<string, (...args: unknown[]) => unknown>;
  const DEL_REFUSED = /del\(\/d\) is Express 4's deprecated alias for delete\(\), and is refused/;

  it("refuses app.del(), undeclared or declared, and serves nothing", async () => {
    const app = secured(express());
    const loose = app as unknown as Loose;
    expect(() => loose["del"]!("/d", handler("undeclared"))).toThrow(DEL_REFUSED);
    expect(() =>
      loose["del"]!("/d", auth().requireScope("fleet:control"), handler("declared"))
    ).toThrow(/Use delete\(\.\.\.\)/);

    const response = await request(app)
      .delete("/d")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(404);
    expect(ran).toEqual([]);
  });

  it("refuses router.del() and route().del() the same way", async () => {
    const router = secured(express.Router());
    const loose = router as unknown as Loose;
    expect(() => loose["del"]!("/d", handler())).toThrow(DEL_REFUSED);
    const route = router.route("/r") as unknown as Loose;
    expect(() => route["del"]!(handler())).toThrow(/deprecated alias for delete\(\)/);

    const app = secured(express());
    app.use(router);
    const response = await request(app).delete("/d");
    expect(response.status).toBe(404);
    expect(ran).toEqual([]);
  });

  it("refuses an undeclared delete on route() from an app and from a router", async () => {
    const app = secured(express());
    const router = secured(express.Router());
    expect(() => router.route("/x").delete(handler())).toThrow(
      /route\(\/x\)\.delete\(<no path>\) was registered without an authorization declaration/
    );
    expect(() => app.route("/y").delete(handler())).toThrow(
      /without an authorization declaration/
    );
    app.use(router);
    expect((await request(app).delete("/x")).status).toBe(404);
    expect((await request(app).delete("/y")).status).toBe(404);
    expect(ran).toEqual([]);
  });

  it("leaves no route method or alias on a target still pointing at Express's own", () => {
    // The audit, made executable: every name Express 4 registers a route
    // under, plus the `del` alias, must no longer be the function Express
    // installed. `express()` COPIES application.js onto each app, so an own
    // property proves nothing; identity with Express's original does.
    const unsecured = express.Router();
    const routeProto = Object.getPrototypeOf(unsecured.route("/p")) as Loose;
    const originals: ReadonlyArray<[string, Loose, Loose]> = [
      ["app", secured(express()) as unknown as Loose, express.application as unknown as Loose],
      ["router", secured(express.Router()) as unknown as Loose, Object.getPrototypeOf(unsecured) as Loose],
      ["route", secured(express.Router()).route("/z") as unknown as Loose, routeProto],
    ];
    const names = [...METHODS.map((m) => m.toLowerCase()), "all", "del", "use", "route"];
    const stillOriginal: string[] = [];
    let checked = 0;
    for (const [label, target, express4] of originals) {
      for (const n of names) {
        if (typeof express4[n] !== "function") continue;
        checked += 1;
        if (target[n] === express4[n]) stillOriginal.push(`${label}.${n}`);
      }
    }
    expect(stillOriginal).toEqual([]);
    // app.del exists in Express 4, so it was among the names checked.
    expect(typeof (express.application as unknown as Loose)["del"]).toBe("function");
    expect(checked).toBeGreaterThan(3 * 30);
  });
});
