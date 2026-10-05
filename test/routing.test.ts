/**
 * @file Every bypass the second review proved, pinned shut.
 *
 * The first design resolved a route's requirement from `req.method` and
 * `req.path`, and the README taught the resolver body
 * `` table[`${method} ${path}`] ?? "none" ``. Once the safe methods were
 * exempted from default-deny, a **miss** on a `GET`, `HEAD` or `OPTIONS`
 * stopped being a loud `500` and became silent public access — and the review
 * found five different ways to miss:
 *
 *   1. `app.all("/cors", mutatingHandler)` answers an `OPTIONS` with the real
 *      handler, and a table keyed `"GET /cors"` does not match `"OPTIONS
 *      /cors"`.
 *   2. Inside `app.use("/api", router)`, `req.path` is `/ships`, so a table
 *      keyed `"GET /api/ships"` never matches.
 *   3. `GET /ships/` — Express's non-strict routing matches the route,
 *      a string key does not.
 *   4. `GET /SHIPS` — Express's case-insensitive routing matches, a string key
 *      does not.
 *   5. `GET /ships/abc` against a route registered as `/ships/:id` — Express
 *      matches, a literal key cannot.
 *
 * None of these is a bug in the table. They are the gap between a hand-written
 * lookup and Express's matcher, and it cannot be closed by writing a better
 * lookup. So the declaration moved to where Express binds the handler, and
 * `secured()` refuses at startup to register a handler that has none.
 *
 * Every case below is driven through a real Express app.
 */

import { createServer, type Server } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import express, { type Express, type Response } from "express";
import request from "supertest";

import {
  createExpressAuth,
  passthrough,
  secured,
} from "../src/express";
import { MESSAGES } from "../src/messages";

const SECRET = "routing-suite-secret";

const ANSWERS: Record<string, unknown> = {
  "operator.token": {
    active: true,
    sub: "user_operator",
    scope: "fleet:control",
    exp: 4102444800,
    kind: "operator",
  },
  "guest.token": {
    active: true,
    sub: "user_guest",
    scope: "",
    exp: 4102444800,
    kind: "operator",
  },
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

const auth = () => createExpressAuth({ url: centerUrl, secret: SECRET });

/** Set by a handler that ran. A side effect nobody authorized is the failure. */
let sideEffects: string[] = [];
beforeEach(() => {
  sideEffects = [];
});

const mutatingHandler = (name: string) => (_req: unknown, res: Response): void => {
  sideEffects.push(name);
  res.json({ ran: name });
};

// ---------------------------------------------------------------------------
// 1. OPTIONS on an app.all route
// ---------------------------------------------------------------------------

describe("1. app.all answers OPTIONS with the real handler", () => {
  /**
   * The review's exhibit A. `app.all("/cors", mutatingHandler)` registers the
   * handler for *every* method, so `OPTIONS /cors` runs it — and it ran, 200,
   * with the side effect fired and no credential presented, because the table
   * had no `"OPTIONS /cors"` key and the miss read as `"none"`. A mutant that
   * made `authorize()` ignore the requirement for `OPTIONS` survived all 150
   * tests of the previous suite.
   */
  const app = (): Express => {
    const application = express();
    const api = secured(express.Router());
    api.all("/cors", auth().requireScope("fleet:control"), mutatingHandler("all"));
    application.use(api);
    return application;
  };

  it("refuses an OPTIONS with no credential, and runs nothing", async () => {
    const response = await request(app()).options("/cors");
    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: { message: MESSAGES.missingToken } });
    expect(sideEffects).toEqual([]);
  });

  it("refuses an OPTIONS whose session lacks the scope", async () => {
    const response = await request(app())
      .options("/cors")
      .set("Authorization", "Bearer guest.token");
    expect(response.status).toBe(403);
    expect(sideEffects).toEqual([]);
  });

  it("allows an OPTIONS that satisfies the declaration", async () => {
    // The enforcement is identical for every method — which means it lets the
    // right OPTIONS through as well as refusing the wrong one. Without this,
    // "401 every OPTIONS" would pass the two cases above.
    const response = await request(app())
      .options("/cors")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(200);
    expect(sideEffects).toEqual(["all"]);
  });

  it("refuses every other method on the same app.all route too", async () => {
    for (const method of ["get", "post", "put", "patch", "delete"] as const) {
      const response = await request(app())[method]("/cors");
      expect(response.status).toBe(401);
    }
    expect(sideEffects).toEqual([]);
  });

  it("refuses to register an app.all route with no declaration", () => {
    const api = secured(express.Router());
    expect(() => api.all("/cors", mutatingHandler("all"))).toThrow(
      /without an authorization declaration/
    );
  });
});

// ---------------------------------------------------------------------------
// 2–5. Everything a path key gets wrong
// ---------------------------------------------------------------------------

describe("2-5. the matcher binds the declaration, whatever the path looked like", () => {
  /**
   * One app with a prefix-mounted router, a literal route and a parameterised
   * one, both declared. Every request below matched a route, so every request
   * below found that route's declaration — there is no lookup to miss.
   */
  const app = (): Express => {
    const application = express();
    const api = secured(express.Router());
    api.get("/ships", auth().requireScope("fleet:control"), mutatingHandler("list"));
    api.get(
      "/ships/:id",
      auth().requireScope("fleet:control"),
      mutatingHandler("one")
    );
    application.use("/api", api);
    return application;
  };

  const refused = async (path: string): Promise<void> => {
    const response = await request(app()).get(path);
    expect([path, response.status]).toEqual([path, 401]);
    expect(response.body).toEqual({ error: { message: MESSAGES.missingToken } });
    expect(sideEffects).toEqual([]);
  };

  it("2. refuses a prefix-mounted route (req.path is /ships, not /api/ships)", async () => {
    await refused("/api/ships");
  });

  it("3. refuses a trailing slash (Express's non-strict routing matches it)", async () => {
    await refused("/api/ships/");
  });

  it("4. refuses a case-variant path (Express's routing is case-insensitive)", async () => {
    await refused("/api/SHIPS");
  });

  it("5. refuses a parameterised route a literal key could never name", async () => {
    await refused("/api/ships/abc123");
  });

  it("serves all four to a caller who satisfies the declaration", async () => {
    // The other half. A design that refused everything would pass the four
    // above and be useless; these prove the declaration was FOUND, not that
    // nothing was.
    for (const path of [
      "/api/ships",
      "/api/ships/",
      "/api/SHIPS",
      "/api/ships/abc123",
    ]) {
      const response = await request(app())
        .get(path)
        .set("Authorization", "Bearer operator.token");
      expect([path, response.status]).toEqual([path, 200]);
    }
    expect(sideEffects).toEqual(["list", "list", "list", "one"]);
  });

  it("refuses a deeper nesting of secured routers just the same", async () => {
    const application = express();
    const outer = secured(express.Router());
    const inner = secured(express.Router());
    inner.get("/:id", auth().requireScope("fleet:control"), mutatingHandler("deep"));
    outer.use("/ships", inner);
    application.use("/api/fleet/v1", outer);

    const denied = await request(application).get("/api/fleet/v1/ships/xyz");
    expect(denied.status).toBe(401);
    expect(sideEffects).toEqual([]);

    const allowed = await request(application)
      .get("/api/fleet/v1/ships/xyz")
      .set("Authorization", "Bearer operator.token");
    expect(allowed.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// 6. HEAD on a guarded GET
// ---------------------------------------------------------------------------

describe("6. HEAD is governed by its GET route's declaration", () => {
  /**
   * This falls out of registration-time declarations rather than being
   * arranged: Express dispatches `HEAD /x` to the `GET /x` route, and the
   * declaration is a handler *on that route*, so it runs. There is no
   * HEAD-to-GET mapping anywhere in the adapter for this shape.
   */
  const app = (): Express => {
    const application = express();
    const api = secured(express.Router());
    api.get("/ships", auth().requireScope("fleet:control"), (_req, res) => {
      res.set("ETag", "W/\"leaky\"").json({ ships: [1, 2, 3] });
    });
    application.use("/api", api);
    return application;
  };

  it("401s a HEAD with no credential, and leaks no headers", async () => {
    const response = await request(app()).head("/api/ships");
    expect(response.status).toBe(401);
    // The route's own ETag is exactly what a HEAD would have leaked — that,
    // the existence of the route and the size of its body. (Express computes
    // an ETag for the 401 envelope too, so the assertion is that the
    // HANDLER's one never got out, not that no ETag exists.)
    expect(response.headers.etag).not.toBe('W/"leaky"');
  });

  it("401s a HEAD on the trailing-slash and case-variant spellings too", async () => {
    for (const path of ["/api/ships/", "/api/SHIPS"]) {
      const response = await request(app()).head(path);
      expect([path, response.status]).toEqual([path, 401]);
    }
  });

  it("403s a HEAD whose session lacks the scope", async () => {
    const response = await request(app())
      .head("/api/ships")
      .set("Authorization", "Bearer guest.token");
    expect(response.status).toBe(403);
  });

  it("serves a HEAD carrying a token that satisfies the route", async () => {
    // The fixture's `head-on-guarded-route-with-valid-token`, through Express.
    // A client that 401s every HEAD passes the three cases above.
    const response = await request(app())
      .head("/api/ships")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(200);
    expect(response.headers.etag).toBe('W/"leaky"');
  });
});

// ---------------------------------------------------------------------------
// 7. Undeclared is never public
// ---------------------------------------------------------------------------

describe("7. an undeclared route is refused on every method", () => {
  it("500s a GET whose resolver returns undefined", async () => {
    // The `?? "none"` this replaced made exactly this request a 200.
    const app = express();
    app.use(auth().guard(() => undefined));
    app.get("/ships", mutatingHandler("list"));

    const response = await request(app).get("/ships");
    expect(response.status).toBe(500);
    expect(response.body).toEqual({
      error: { message: MESSAGES.undeclaredRoute },
    });
    expect(sideEffects).toEqual([]);
  });

  it("500s every safe method, with and without a valid credential", async () => {
    const app = express();
    app.use(auth().guard(() => undefined));
    app.all("/ships", mutatingHandler("all"));

    for (const method of ["get", "head", "options", "post", "delete"] as const) {
      for (const header of [undefined, "Bearer operator.token"]) {
        const pending = request(app)[method]("/ships");
        const response = await (header === undefined
          ? pending
          : pending.set("Authorization", header));
        expect([method, header, response.status]).toEqual([method, header, 500]);
      }
    }
    expect(sideEffects).toEqual([]);
  });

  it("does not call the center for an undeclared route", async () => {
    // A defect in our own routing table must not become load on auth-service.
    const calls: string[] = [];
    const app = express();
    const counting = createExpressAuth({
      introspect: (token: string) => {
        calls.push(token);
        return Promise.resolve({ state: "inactive" as const });
      },
    });
    app.use(counting.guard(() => undefined));
    app.get("/ships", mutatingHandler("list"));

    const response = await request(app)
      .get("/ships")
      .set("Authorization", "Bearer operator.token");
    expect(response.status).toBe(500);
    expect(calls).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 8. Registration-time refusal
// ---------------------------------------------------------------------------

describe("8. secured() refuses an undeclared handler at registration time", () => {
  const handler = (_req: unknown, res: Response): void => {
    res.json({ ran: true });
  };

  it("throws for every route-registering method", () => {
    for (const method of [
      "get",
      "post",
      "put",
      "patch",
      "delete",
      "head",
      "options",
      "all",
      "trace",
    ] as const) {
      const api = secured(express.Router()) as unknown as Record<
        string,
        (...args: unknown[]) => unknown
      >;
      expect(() => api[method]?.("/x", handler)).toThrow(
        /without an authorization declaration/
      );
    }
  });

  it("names the route and says how to fix it", () => {
    const api = secured(express.Router());
    expect(() => api.get("/ships/:id", handler)).toThrow(/\/ships\/:id/);
    expect(() => api.get("/ships/:id", handler)).toThrow(/allowPublic/);
    expect(() => api.get("/ships/:id", handler)).toThrow(/requireScope/);
  });

  it("accepts a declaration in first position, and refuses one after a handler", () => {
    // Position is the rule, not presence — see registration.test.ts for every
    // ordering, for `route()` chains and for `use()`.
    const api = secured(express.Router());
    const a = auth();
    expect(() => api.get("/a", a.requireSession(), handler)).not.toThrow();
    expect(() => api.get("/b", handler as never, a.allowPublic())).toThrow(
      /before its authorization declaration/
    );
    expect(() => api.get("/c", [a.requireSession(), handler] as never)).not.toThrow();
  });

  it("throws for router.route(...).get(...), the chaining spelling", () => {
    const api = secured(express.Router());
    expect(() => api.route("/x").get(handler)).toThrow(
      /without an authorization declaration/
    );
    expect(() =>
      api.route("/y").get(auth().requireSession(), handler)
    ).not.toThrow();
  });

  it("does not reach a Route taken off the prototype, and says so", () => {
    // `secured()` replaces `route` as an OWN property of the router, so
    // `Object.getPrototypeOf(router).route.call(router, "/a")` returns a raw
    // Route this package never sees. There is no cheap way to guard a Route
    // the patched `route()` never returned — an interposed prototype would be
    // a global mutation of Express itself — so it is listed in the README
    // under "What this package does not protect", beside `router.stack.push`,
    // and pinned here so the gap is a known one rather than folklore.
    const api = secured(express.Router());
    const raw = (
      Object.getPrototypeOf(api) as {
        route(path: string): { get(h: unknown): unknown };
      }
    ).route.call(api, "/bypass");
    expect(() => raw.get(handler)).not.toThrow();
  });

  it("throws for use() of a bare middleware, and names the escape hatch", () => {
    const api = secured(express.Router());
    expect(() => api.use(handler)).toThrow(/neither a declaration nor/);
    expect(() => api.use(handler)).toThrow(/passthrough/);
  });

  it("accepts use() of a vouched-for passthrough, a guard, or a secured router", () => {
    const api = secured(express.Router());
    expect(() =>
      api.use(passthrough(express.json(), "parses bodies; never answers"))
    ).not.toThrow();
    expect(() => api.use(auth().guard(() => "session"))).not.toThrow();
    expect(() => api.use("/nested", secured(express.Router()))).not.toThrow();
  });

  it("accepts use() of an error handler, which cannot serve a route", () => {
    const api = secured(express.Router());
    const onError = (
      err: unknown,
      _req: unknown,
      res: Response,
      _next: unknown
    ): void => {
      res.status(500).json({ error: { message: String(err) } });
    };
    expect(() => api.use(onError as never)).not.toThrow();
  });

  it("leaves Express's settings getter alone when the app itself is secured", () => {
    // `app.get("view engine")` is a SETTING, not a route. Refusing it would
    // break the app at startup for a call that registers nothing.
    const application = secured(express());
    application.set("trust proxy", 1);
    expect(application.get("trust proxy")).toBe(1);
    expect(() => application.get("/x", handler)).toThrow(
      /without an authorization declaration/
    );
  });

  it("is idempotent", () => {
    const api = secured(express.Router());
    expect(secured(api)).toBe(api);
    // Patching twice would make the assertion run twice, which is harmless,
    // but it would also stack a bound call per wrap. One wrap, once.
    expect(() => api.get("/x", auth().allowPublic(), handler)).not.toThrow();
  });

  it("still registers the route once the declaration is there", async () => {
    const application = express();
    const api = secured(express.Router());
    api.get("/open", auth().allowPublic(), (_req, res) => {
      res.json({ ok: true });
    });
    application.use(api);
    const response = await request(application).get("/open");
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// What a resolver is handed
// ---------------------------------------------------------------------------

describe("a resolver is handed the method and nothing else", () => {
  it("sees exactly one property, whatever the request's path was", async () => {
    // S4. The resolver used to be handed `path`, `baseUrl`, `originalUrl` and
    // `route` — which is an invitation to write the table this whole design
    // exists to delete. Inside a router mounted at /api, `req.path` is
    // `/ships` and not `/api/ships`; it has not been through Express's
    // matcher; a trailing slash, a case-variant and a `:parameter` all miss a
    // literal key; and `req.route` is undefined in a `use` mount because no
    // route layer has matched yet. None of it is reachable any more.
    const seen: Record<string, unknown>[] = [];
    const application = express();
    const api = express.Router();
    api.use(
      auth().guard((context) => {
        seen.push({ ...context, keys: Object.keys(context) });
        return "none";
      })
    );
    api.get("/ships", (_req, res) => {
      res.json({ ok: true });
    });
    application.use("/api", api);

    await request(application).get("/api/ships?fleet=1");

    expect(seen).toHaveLength(1);
    expect(seen[0]?.keys).toEqual(["method"]);
    expect(seen[0]?.method).toBe("GET");
  });

  it("reads HEAD as GET, because Express dispatches it to the GET handler", async () => {
    const seen: string[] = [];
    const application = express();
    application.use(
      auth().guard(({ method }) => {
        seen.push(method);
        return "none";
      })
    );
    application.get("/ships", (_req, res) => {
      res.json({ ok: true });
    });

    await request(application).head("/ships");
    expect(seen).toEqual(["GET"]);
  });
});

// ---------------------------------------------------------------------------
// 9. Express answers OPTIONS itself, before any route layer runs
// ---------------------------------------------------------------------------

describe("9. Express's automatic OPTIONS never reaches the declaration", () => {
  /**
   * P3 used to read "a declared requirement is enforced identically for every
   * method", which is false for the one method Express answers on its own
   * behalf. When a request's path matches a route but its method does not,
   * Express's router replies `200` with an `Allow:` header **before** any
   * layer on that route runs — so a declaration attached to the route does
   * not execute, no handler runs, and nothing is authorized away, but the
   * route's existence and its method list are disclosed to an anonymous
   * caller.
   *
   * P3 now says "every method Express dispatches to the route", and the
   * disclosure is listed under "What this package does not protect". Pinned
   * here so a future change to it is noticed rather than assumed.
   */
  it("answers OPTIONS with Allow, runs no handler and asks no center", async () => {
    const calls: string[] = [];
    const counting = createExpressAuth({
      introspect: (token: string) => {
        calls.push(token);
        return Promise.resolve({ state: "inactive" as const });
      },
    });

    const application = express();
    const api = secured(express.Router());
    api.get("/ships", counting.requireScope("fleet:control"), mutatingHandler("list"));
    application.use("/api", api);

    const response = await request(application)
      .options("/api/ships")
      .set("Authorization", "Bearer operator.token");

    expect(response.status).toBe(200);
    expect(response.headers.allow).toContain("GET");
    expect(sideEffects).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("still enforces the declaration on a route that DOES answer OPTIONS", async () => {
    // The distinction that makes the wording honest: `app.all` (and an
    // explicit `.options`) registers a layer for OPTIONS, so Express
    // dispatches to the route and the declaration runs. Section 1 above
    // covers that case; this is the contrast.
    const application = express();
    const api = secured(express.Router());
    api.all("/ships", auth().requireScope("fleet:control"), mutatingHandler("all"));
    application.use("/api", api);

    const response = await request(application).options("/api/ships");
    expect(response.status).toBe(401);
    expect(sideEffects).toEqual([]);
  });
});
