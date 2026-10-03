/**
 * @file The fourth review's findings about the brands themselves.
 *
 * Three separate claims, all about the same mechanism:
 *
 * **B1.** `notFound()` was an authorization bypass. `secured(express())
 * .use("/admin", notFound(mutatingHandler))` registered without complaint and
 * `POST /admin/delete-everything` answered `200` with zero calls to the
 * center: `assertUseSafe` ignored the path argument and a terminal vouched for
 * itself wherever it appeared, so `notFound()` was a way to spell "mount this
 * handler for every method under this prefix, undeclared". The brand was also
 * applied to the caller's own function *before* the registration was refused,
 * so a refused function stayed acceptable everywhere else.
 *
 * **S4.** `use()` lets an arity-4 error handler through unbranded, because
 * Express invokes one only with an error already in flight. The check is
 * `length >= 4`; relaxed to `>= 3` it would accept every ordinary middleware
 * and every `express.Router()`, which is itself a function of arity 3.
 *
 * **S5.** The brands are WeakMaps and WeakSets, never properties on the
 * function, so nothing a caller can write onto a handler vouches for it.
 */

import express, { type NextFunction, type Request, type Response } from "express";
import request from "supertest";

import type { CenterAnswer } from "../src/center";
import {
  createExpressAuth,
  notFound,
  passthrough,
  secured,
} from "../src/express";

const ACTIVE: CenterAnswer = {
  state: "active",
  identity: { sub: "user_operator", kind: "operator", scopes: ["fleet:control"] },
};

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

let ran: string[] = [];
beforeEach(() => {
  ran = [];
});

const handler =
  (name = "handler") =>
  (_req: unknown, res: Response): void => {
    ran.push(name);
    res.json({ ran: name });
  };

// ---------------------------------------------------------------------------
// B1
// ---------------------------------------------------------------------------

describe("B1. a notFound() terminal cannot be used as a mount", () => {
  const mutating = () =>
    notFound((_req: Request, res: Response) => {
      ran.push("mutating");
      res.status(200).json({ deleted: "everything" });
    });

  it("refuses the path form outright — the bypass as reported", () => {
    const app = secured(express());
    expect(() => app.use("/admin", mutating() as never)).toThrow(
      /on a path or alongside other handlers/
    );
  });

  it("refuses it with a RegExp or an array path too", () => {
    const app = secured(express());
    expect(() => app.use(/^\/admin/ as never, mutating() as never)).toThrow(
      /on a path or alongside other handlers/
    );
    expect(() =>
      app.use(["/admin", "/ops"] as never, mutating() as never)
    ).toThrow(/on a path or alongside other handlers/);
  });

  it("refuses it when it is not the sole handler of the call", () => {
    const app = secured(express());
    expect(() =>
      app.use(
        passthrough(express.json(), "parses bodies; never answers") as never,
        mutating() as never
      )
    ).toThrow(/on a path or alongside other handlers/);
  });

  it("refuses it on a route method and on a route() chain", () => {
    const api = secured(express.Router());
    expect(() => api.get("/admin", mutating() as never)).toThrow(
      /without an authorization declaration/
    );
    expect(() => api.post("/admin", mutating() as never)).toThrow(
      /without an authorization declaration/
    );
    expect(() => api.all("/admin", mutating() as never)).toThrow(
      /without an authorization declaration/
    );
    expect(() => api.route("/admin").get(mutating() as never)).toThrow(
      /without an authorization declaration/
    );
  });

  it("does not brand the function the caller passed in", () => {
    // The brand goes on the wrapper. A caller that keeps a reference to its
    // own function must not find that this package has vouched for it.
    const bare = (_req: Request, res: Response): void => {
      res.json({ ok: true });
    };
    notFound(bare);
    const api = secured(express.Router());
    expect(() => api.use(bare as never)).toThrow(/neither a declaration nor/);
    expect(() => api.get("/x", bare as never)).toThrow(
      /without an authorization declaration/
    );
  });

  it("does not make a refused wrapper acceptable anywhere else", () => {
    // The wrapper IS branded, and that is fine — the only position it is
    // accepted in is the one sound position. A refused registration does not
    // leave a usable catch-all lying around.
    const app = secured(express());
    const wrapper = mutating();
    expect(() => app.use("/admin", wrapper as never)).toThrow();
    expect(() => app.get("/admin", wrapper as never)).toThrow(
      /without an authorization declaration/
    );
  });

  it("accepts the one sound spelling, and it still answers", async () => {
    const app = express();
    const secure = secured(express.Router());
    secure.get("/known", auth().allowPublic(), handler("known"));
    expect(() =>
      secure.use(
        notFound((_req: Request, res: Response) =>
          res.status(404).json({ error: { message: "not found" } })
        )
      )
    ).not.toThrow();
    app.use(secure);

    const response = await request(app).get("/unknown");
    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: { message: "not found" } });
  });
});

describe("B1. a notFound() terminal cannot answer a success", () => {
  it("forces 404 when the handler tries to answer 200", async () => {
    // The position rule alone would still leave `app.use(notFound(h))` usable
    // as a public catch-all serving whatever it liked. The wrapper makes the
    // terminal unable to succeed: 404 before, clamped during, forced after.
    const { auth: counting, calls } = countingAuth();
    const app = express();
    const secure = secured(express.Router());
    secure.get("/known", counting.requireSession(), handler("known"));
    secure.use(
      notFound((_req: Request, res: Response) => {
        ran.push("terminal");
        res.status(200).json({ deleted: "everything" });
      })
    );
    app.use(secure);

    const response = await request(app).post("/admin/delete-everything").send({});
    expect(response.status).toBe(404);
    // The handler ran — it is the app's own 404 body — but it could not make
    // the answer a success, and nothing was authorized on the way.
    expect(ran).toEqual(["terminal"]);
    expect(calls).toEqual([]);
  });

  it("forces 404 when the handler sets no status at all", async () => {
    const app = express();
    const secure = secured(express.Router());
    secure.get("/known", auth().allowPublic(), handler("known"));
    secure.use(
      notFound((_req: Request, res: Response) => {
        res.json({ error: { message: "not found" } });
      })
    );
    app.use(secure);

    expect((await request(app).get("/unknown")).status).toBe(404);
  });

  it("forces 404 when the handler sets the status and returns without sending", async () => {
    // The after-the-fact check, on the path where nothing has gone out yet.
    const app = express();
    const secure = secured(express.Router());
    secure.get("/known", auth().allowPublic(), handler("known"));
    secure.use(
      notFound((_req: Request, res: Response) => {
        res.statusCode = 200;
        setImmediate(() => res.end());
      })
    );
    app.use(secure);

    expect((await request(app).get("/unknown")).status).toBe(404);
  });

  it("lets the handler choose another failing status", async () => {
    // The clamp is about success, not about the exact code: a terminal that
    // wants 410 Gone gets 410.
    const app = express();
    const secure = secured(express.Router());
    secure.get("/known", auth().allowPublic(), handler("known"));
    secure.use(
      notFound((_req: Request, res: Response) => {
        res.status(410).json({ error: { message: "gone" } });
      })
    );
    app.use(secure);

    expect((await request(app).get("/unknown")).status).toBe(410);
  });

  it("hands a normal res.status back before calling next(err)", async () => {
    // The clamp is for the terminal, not for the error handler behind it,
    // which has to be able to answer 500.
    const app = express();
    const secure = secured(express.Router());
    secure.get("/known", auth().allowPublic(), handler("known"));
    secure.use(
      notFound((_req: Request, _res: Response, next: NextFunction) => {
        next(new Error("boom"));
      })
    );
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- Express tells an error handler apart by arity (four parameters), so the unused ones must stay
    const onError = (_e: unknown, _req: Request, res: Response, _n: NextFunction): void => {
      res.status(500).json({ error: { message: "internal" } });
    };
    secure.use(onError as never);
    app.use(secure);

    expect((await request(app).get("/unknown")).status).toBe(500);
  });

  it("refuses a non-function, and returns a wrapper of arity 3", () => {
    expect(() => notFound(undefined as never)).toThrow(/handler function/);
    const wrapper = notFound((_req: Request, res: Response) => res.end()) as unknown as {
      length: number;
    };
    // Never 4: an arity-4 layer is an error handler to Express and would not
    // run on an ordinary unmatched request at all.
    expect(wrapper.length).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// S4
// ---------------------------------------------------------------------------

describe("S4. use() refuses a bare arity-3 middleware and a bare Router", () => {
  it("refuses an arity-3 middleware that vouches for nothing", () => {
    const api = secured(express.Router());
    // eslint-disable-next-line @typescript-eslint/no-unused-vars, @typescript-eslint/no-empty-function -- Express tells handlers apart by arity, so the unused parameters (and the empty body) must stay
    const three = (_req: Request, _res: Response, _next: NextFunction): void => {};
    expect(three.length).toBe(3);
    expect(() => api.use(three as never)).toThrow(/neither a declaration nor/);
    expect(() => api.use("/x", three as never)).toThrow(
      /neither a declaration nor/
    );
  });

  it("refuses an arity-3 middleware that would answer", () => {
    const api = secured(express.Router());
    expect(() => api.use(handler() as never)).toThrow(
      /neither a declaration nor/
    );
  });

  it("refuses a bare express.Router(), which is itself a function of arity 3", () => {
    const bare = express.Router();
    expect(bare.length).toBe(3);
    const app = secured(express());
    expect(() => app.use(bare)).toThrow(/neither a declaration nor/);
    expect(() => app.use("/api/fleet/v1", bare)).toThrow(
      /neither a declaration nor/
    );
  });

  it("still accepts the arity-4 error handler it is meant to accept", () => {
    const api = secured(express.Router());
    // eslint-disable-next-line @typescript-eslint/no-unused-vars, @typescript-eslint/no-empty-function -- Express tells handlers apart by arity, so the unused parameters (and the empty body) must stay
    const four = (_e: unknown, _req: Request, _res: Response, _n: NextFunction): void => {};
    expect(four.length).toBe(4);
    expect(() => api.use(four as never)).not.toThrow();
  });

  it("accepts the generated router when a guard leads the mount", () => {
    // The README's construct, in the spelling that actually works: this is
    // what B2 was about.
    const app = secured(express());
    const generated = express.Router();
    generated.get("/ships", (_req, res) => {
      res.json({ ships: [] });
    });
    expect(() =>
      app.use(
        "/api/fleet/v1",
        auth().guard(({ method }) =>
          method === "GET" ? "session" : "fleet:control"
        ),
        generated
      )
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// S5
// ---------------------------------------------------------------------------

describe("S5. a brand cannot be forged with a property", () => {
  const NAMES = [
    "__declares",
    "__passthrough",
    "__terminal",
    "__guard",
    "__secured",
    "declares",
    "passthrough",
    "notFound",
    "requires",
    "brand",
  ];

  it.each(NAMES)("an own property %s does not vouch for a handler", (name) => {
    const forged = handler("forged") as unknown as Record<string, unknown>;
    forged[name] = "session";
    const api = secured(express.Router());
    expect(() => api.use(forged as never)).toThrow(/neither a declaration nor/);
    expect(() => api.get("/x", forged as never)).toThrow(
      /without an authorization declaration/
    );
  });

  it("nor a Symbol-keyed property, nor one on the prototype", () => {
    const forged = handler("forged") as unknown as Record<
      string | symbol,
      unknown
    >;
    forged[Symbol.for("introspection.identity")] = "session";
    forged[Symbol.for("introspection.requires")] = "session";
    Object.setPrototypeOf(forged, {
      __declares: "session",
      __passthrough: true,
    });
    const api = secured(express.Router());
    expect(() => api.use(forged as never)).toThrow(/neither a declaration nor/);
  });

  it("nor copying a real declaration's own properties onto another function", () => {
    // A real declaration is a function this package MADE and remembered in a
    // WeakMap. Cloning its own properties copies nothing that matters.
    const real = auth().requireSession();
    const clone = handler("clone") as unknown as Record<string, unknown>;
    for (const key of Reflect.ownKeys(real)) {
      const descriptor = Object.getOwnPropertyDescriptor(real, key);
      if (descriptor?.configurable === true) {
        Object.defineProperty(clone, key, descriptor);
      }
    }
    const api = secured(express.Router());
    expect(() => api.get("/x", clone as never, handler())).toThrow(
      /without an authorization declaration/
    );
  });

  it("and a forged handler that reached a route is never served", async () => {
    // The registration throw is the point, but prove the negative too: an app
    // that somehow booted with a forged brand still has an undeclared route.
    const app = express();
    const api = secured(express.Router());
    const forged = handler("forged") as unknown as Record<string, unknown>;
    forged.__declares = "none";
    expect(() => api.get("/x", forged as never)).toThrow();
    app.use(api);

    const response = await request(app).get("/x");
    expect(response.status).toBe(404);
    expect(ran).toEqual([]);
  });
});
