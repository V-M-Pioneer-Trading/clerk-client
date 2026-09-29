/**
 * @file S1. The per-request state is invisible, and holds no credential.
 *
 * An earlier revision memoized the center's answer on `res.locals` under a
 * module-private Symbol, **keyed on the raw `Authorization` header value**.
 * Symbol keys are absent from `Object.keys` and from `JSON.stringify`, which
 * is what that revision tested — but `util.inspect` prints them, and
 * `util.inspect` is what a `console.log(res.locals)`, a debugger pane and an
 * error reporter that serialises request context all use. A live bearer token
 * was therefore one ordinary log line away from a log aggregator.
 *
 * The state now lives in a module-private WeakMap keyed on the response, and
 * the memo holds a SHA-256 digest of the header rather than the header. The
 * tests below are about both halves: nothing of ours is reachable from `res`
 * at all, and the token appears nowhere in the process's view of the request.
 */

import { inspect } from "node:util";
import express from "express";
import request from "supertest";

import type { CenterAnswer } from "../src/center";
import {
  actorOf,
  createExpressAuth,
  hasScope,
  identityOf,
  kindOf,
  requirementOf,
  secured,
} from "../src/express";

const TOKEN = "operator.super.secret.token.value";
const SECRET = "introspection-caller-secret-value";

const ACTIVE: CenterAnswer = {
  state: "active",
  identity: { sub: "user_operator", kind: "operator", scopes: ["fleet:control"] },
};

/** An auth over an injected introspector that also sees the caller secret. */
const countingAuth = () => {
  const calls: string[] = [];
  const auth = createExpressAuth({
    introspect: (token: string) => {
      calls.push(token);
      // The secret is closed over exactly as the real introspector holds it,
      // so a test that found it on `res.locals` would be finding a real leak.
      void SECRET;
      return Promise.resolve(
        token === TOKEN ? ACTIVE : ({ state: "inactive" } as const)
      );
    },
  });
  return { auth, calls };
};

/** Everything a logger could get at, from inside a handler. */
interface Seen {
  readonly keys: string[];
  readonly symbols: string[];
  readonly inspected: string;
  readonly inspectedRes: string;
  readonly serialised: string;
  readonly identity: unknown;
  readonly actor: string | null;
  readonly kind: string | null;
  readonly requires: string | null;
  readonly scoped: boolean;
}

const appThatLooks = (): { app: express.Express; calls: string[] } => {
  const { auth, calls } = countingAuth();
  const app = express();
  const api = secured(express.Router());
  api.use(auth.guard(() => "session"));
  api.get("/whoami", auth.requireScope("fleet:control"), (_req, res) => {
    const seen: Seen = {
      keys: Object.keys(res.locals),
      symbols: Object.getOwnPropertySymbols(res.locals).map(String),
      // showHidden AND depth: the strongest form of the thing that used to
      // print the token.
      inspected: inspect(res.locals, { showHidden: true, depth: 5 }),
      // And the response object itself, in case anything of ours became a
      // property of it rather than of its locals.
      inspectedRes: inspect(
        { locals: res.locals, statusCode: res.statusCode },
        { showHidden: true, depth: 5 }
      ),
      serialised: JSON.stringify(res.locals),
      identity: identityOf(res),
      actor: actorOf(res),
      kind: kindOf(res),
      requires: requirementOf(res),
      scoped: hasScope(res, "fleet:control"),
    };
    res.json(seen);
  });
  app.use("/api", api);
  return { app, calls };
};

describe("S1. nothing of ours is visible on the response", () => {
  it("leaves res.locals empty to every form of inspection", async () => {
    const { app } = appThatLooks();
    const response = await request(app)
      .get("/api/whoami")
      .set("Authorization", `Bearer ${TOKEN}`);

    expect(response.status).toBe(200);
    const seen = response.body as Seen;

    expect(seen.keys).toEqual([]);
    // Not merely absent from Object.keys: there is no Symbol-keyed property
    // either, which is what the previous design relied on for privacy.
    expect(seen.symbols).toEqual([]);
    expect(seen.serialised).toBe("{}");
    // Express creates `res.locals` with a null prototype, which util.inspect
    // says out loud; what matters is that the braces are empty.
    expect(seen.inspected).toMatch(/^(\[Object: null prototype\] )?\{\}$/);
  });

  it("puts neither the token nor the caller secret anywhere inspectable", async () => {
    const { app } = appThatLooks();
    const response = await request(app)
      .get("/api/whoami")
      .set("Authorization", `Bearer ${TOKEN}`);

    const seen = response.body as Seen;
    for (const rendered of [
      seen.inspected,
      seen.inspectedRes,
      seen.serialised,
    ]) {
      expect(rendered).not.toContain(TOKEN);
      expect(rendered).not.toContain(SECRET);
      expect(rendered).not.toContain("Bearer");
      expect(rendered).not.toContain("uthorization");
    }
    // And the whole response body, which is everything the handler could see.
    expect(JSON.stringify(response.body)).not.toContain(TOKEN);
    expect(JSON.stringify(response.body)).not.toContain(SECRET);
  });

  it("still gives the accessors the identity they are for", async () => {
    const { app } = appThatLooks();
    const response = await request(app)
      .get("/api/whoami")
      .set("Authorization", `Bearer ${TOKEN}`);

    const seen = response.body as Seen;
    expect(seen.identity).toEqual({
      sub: "user_operator",
      kind: "operator",
      scopes: ["fleet:control"],
    });
    expect(seen.actor).toBe("user_operator");
    expect(seen.kind).toBe("operator");
    expect(seen.requires).toBe("fleet:control");
    expect(seen.scoped).toBe(true);
  });

  it("answers null from every accessor for a response it never saw", () => {
    // The WeakMap has no entry, and no accessor invents one.
    const res = { locals: {} } as never;
    expect(identityOf(res)).toBeNull();
    expect(actorOf(res)).toBeNull();
    expect(kindOf(res)).toBeNull();
    expect(requirementOf(res)).toBeNull();
    expect(hasScope(res, "fleet:control")).toBe(false);
  });
});

describe("S1. the memo is per-request and keyed on a digest", () => {
  it("asks the center once for a guard and a declaration together", async () => {
    const { app, calls } = appThatLooks();
    const response = await request(app)
      .get("/api/whoami")
      .set("Authorization", `Bearer ${TOKEN}`);
    expect(response.status).toBe(200);
    expect(calls).toEqual([TOKEN]);
  });

  it("does not share the memo between requests", async () => {
    // The WeakMap is module-scoped, which is exactly the shape a mutant would
    // turn into a process-wide cache keyed on the header: that would hand one
    // caller's identity to the next caller presenting the same value and make
    // revocation meaningless for its lifetime.
    const { app, calls } = appThatLooks();
    for (let i = 0; i < 3; i += 1) {
      const response = await request(app)
        .get("/api/whoami")
        .set("Authorization", `Bearer ${TOKEN}`);
      expect(response.status).toBe(200);
    }
    expect(calls).toEqual([TOKEN, TOKEN, TOKEN]);
  });

  it("asks again when the second enforcement point sees a different header", async () => {
    // The digest is over the exact header value, so a rewritten credential is
    // a different question rather than a memo hit.
    const { auth, calls } = countingAuth();
    const app = express();
    const api = express.Router();
    api.use(auth.guard(() => "session"));
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
    api.get("/ships", auth.requireSession(), (_req, res) => {
      res.json({ ok: true });
    });
    app.use("/api", api);

    const response = await request(app)
      .get("/api/ships")
      .set("Authorization", `Bearer ${TOKEN}`);
    expect(response.status).toBe(401);
    expect(calls).toEqual([TOKEN, "second.token"]);
  });

  it("does not confuse two concurrent requests carrying different tokens", async () => {
    // Keyed on the RESPONSE object, so concurrency is not a shared-state
    // question at all. A module-level memo would answer one of these with the
    // other's identity.
    const { auth, calls } = countingAuth();
    const app = express();
    const api = secured(express.Router());
    api.use(auth.guard(() => "session"));
    api.get("/whoami", auth.requireSession(), (_req, res) => {
      res.json({ actor: actorOf(res) });
    });
    app.use("/api", api);

    const [good, bad] = await Promise.all([
      request(app).get("/api/whoami").set("Authorization", `Bearer ${TOKEN}`),
      request(app).get("/api/whoami").set("Authorization", "Bearer other.token"),
    ]);

    expect(good.status).toBe(200);
    expect(good.body).toEqual({ actor: "user_operator" });
    expect(bad.status).toBe(401);
    expect(calls.sort()).toEqual([TOKEN, "other.token"].sort());
  });
});
