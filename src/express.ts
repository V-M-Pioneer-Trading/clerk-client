/**
 * @file Express 4 adapter.
 *
 * Express is a **development dependency of this repository only**: nothing
 * here imports it at runtime *or at type level*. The interfaces below are the
 * minimum shape the adapter touches, declared locally, so the shipped `.d.ts`
 * mentions no package a consumer might not have — a consumer with
 * `skipLibCheck: false` and no `@types/express` typechecks against this file,
 * which is the claim CI proves with two separate tarball probes. Real Express
 * `Request`/`Response`/`RequestHandler` values are structurally assignable in
 * both directions, so nothing here needs a cast.
 *
 * ## The rule this file exists to enforce
 *
 * **A route with no declaration is never served, for any method.** Not for
 * `GET`, not for `HEAD`, not for `OPTIONS`. "Public" is a thing a route says
 * out loud — {@link ExpressAuth.allowPublic} — and never a thing that happens
 * because a lookup missed.
 *
 * Declarations live **at registration**, next to the handler, where Express's
 * own matcher binds them:
 *
 * ```ts
 * const api = secured(express.Router());
 * api.get("/ships", auth.requireSession(), listShips);
 * api.post("/ships/:id/navigate", auth.requireScope("fleet:control"), navigate);
 * api.get("/health", auth.allowPublic(), health);
 * app.use("/api/fleet/v1", api);
 * ```
 *
 * Whatever Express matched, it matched the declaration with it. Prefixes,
 * trailing slashes, case, parameters and `app.all` answering an `OPTIONS` are
 * all Express's business and stay Express's business.
 *
 * A table lookup cannot be made equivalent to Express's matcher, so this
 * adapter does not try — and that is also why {@link ExpressAuth.guard}'s
 * resolver is handed the **method and nothing else**. A previous revision
 * handed it `path`, `baseUrl` and `originalUrl`, which invited exactly the
 * table the design exists to delete: inside a router mounted at a prefix
 * `req.path` is the path *after* the prefix, it has not been through Express's
 * matcher, and a trailing slash, a case-variant path or a `:parameter` all miss
 * a literal key. There is now nothing to key on but the method.
 *
 * ## Position is part of the rule
 *
 * A declaration **must be the first handler of a route**. Express runs a
 * route's handlers in registration order, so a declaration that comes second
 * is a handler that already answered — `api.get("/x", handler, requireScope(…))`
 * serves `/x` to anyone, and a test that only checks "a declaration is present
 * somewhere" passes. The only things allowed before a declaration are
 * {@link passthrough} items, which have been vouched for as never answering.
 *
 * More than one declaration on a route is **refused**. Two declarations are
 * two center calls for one request and two answers to reconcile; there is no
 * reading of "and also" worth the ambiguity.
 *
 * {@link secured} enforces both **at registration time**, so the process does
 * not start. An undeclared route cannot exist, rather than being detected once
 * a request finds it.
 *
 * **The guard trusts `req.method`.** Any method-override middleware must be
 * mounted *before* it, or a `POST` arrives here as whatever the override said.
 * This package ignores `X-HTTP-Method-Override` itself and always will.
 */

import { createHash } from "node:crypto";
import { METHODS } from "node:http";

import type { CenterAnswer, Introspector } from "./center";
import { createIntrospector } from "./center";
import type { Authorizer } from "./core";
import { authorizationLines, createAuthorizer, isSafeMethod } from "./core";
import { MESSAGES } from "./messages";
import type {
  Decision,
  Identity,
  IntrospectionConfig,
  Kind,
  RouteRequirement,
} from "./types";

/**
 * The part of an Express `Request` this adapter reads: the method, one header,
 * and how many times that header was sent. Nothing else, because nothing else
 * is safe to decide on — see the file comment. A real `Request` satisfies it;
 * declaring it locally keeps `express` out of the public types.
 */
export interface RequestLike {
  /** The HTTP method, as the framework parsed it. Never an override header. */
  readonly method: string;
  /**
   * One request header, case-insensitively. Express returns the joined value
   * for a repeated header and an array only for `set-cookie`; both shapes are
   * accepted here so a real `Request` is assignable without a cast.
   */
  header(name: string): string | string[] | undefined;
  /**
   * Node's `rawHeaders`: every header line as sent, alternating name and
   * value. Read for one thing only — how many `Authorization` lines arrived,
   * because Node keeps the first and discards the rest, so `header()` cannot
   * tell one from two. See {@link authorizationLines}.
   *
   * Required rather than optional: a request double without it would
   * otherwise be read as carrying exactly one line, which is the defect.
   */
  readonly rawHeaders: readonly string[];
}

/** The part of an Express `Response` this adapter writes. */
export interface ResponseLike {
  locals: Record<string, unknown>;
  status(code: number): ResponseLike;
  json(body: unknown): unknown;
  /**
   * The status as it stands. Optional so a minimal test double is still
   * assignable; a real `Response` has it, and {@link notFound} reads it to
   * refuse to let a terminal answer a success.
   */
  readonly statusCode?: number;
  /** Whether the head has already gone out, for the same reason. */
  readonly headersSent?: boolean;
}

/** Express's `next`. An error argument makes Express fail the request. */
export type NextLike = (err?: unknown) => void;

/** Structurally an Express `RequestHandler`, without naming one. */
export type HandlerLike = (
  req: RequestLike,
  res: ResponseLike,
  next: NextLike
) => void;

/*
 * Where this package's own per-request state lives.
 *
 * NOT on `res.locals`, under any key. `res.locals` is the host application's
 * namespace and it is *printed*: `util.inspect(res.locals)`, a debugger, an
 * error reporter that serialises context, or a `console.log` in a handler all
 * walk it — and `util.inspect` shows Symbol-keyed properties too, so a Symbol
 * key hides a value from `Object.keys` and from `JSON.stringify` but not from
 * the place a raw `Authorization` header actually leaks from. An earlier
 * revision memoized the center's answer there *together with the raw header
 * value it was about*, which put a live credential one `console.log(res.locals)`
 * away from a log aggregator.
 *
 * So: one module-private WeakMap keyed on the response object. It is invisible
 * to every form of inspection of `res` (there is no property to find), it dies
 * with the response, and it cannot be read without a reference to this
 * module's own binding. One mechanism for all three pieces of state rather
 * than two — the identity carries no secret, but a second mechanism is a
 * second thing to reason about.
 *
 * The memo does not hold the header value either: it holds a SHA-256 digest of
 * it, which is all that is needed to answer "is this the same credential the
 * first enforcement point asked about?".
 */
interface RequestState {
  /** The center's verdict for this request, once something has enforced. */
  identity?: Identity | null;
  /** What the matched route declared, or null when it declared nothing. */
  requires?: DeclaredRequirement | null;
  /** One request's memoized center answer, and a digest of the header it was about. */
  memo?: { readonly digest: string; readonly answer: Promise<CenterAnswer> };
}

const requestState = new WeakMap<object, RequestState>();

const stateOf = (res: ResponseLike): RequestState => {
  let state = requestState.get(res);
  if (state === undefined) {
    state = {};
    requestState.set(res, state);
  }
  return state;
};

/**
 * A digest of one `Authorization` header value, never the value.
 *
 * SHA-256 and not a truncation or a length: the memo key must distinguish two
 * different credentials with certainty, and must not be reversible into the
 * one it stands for if it is ever printed.
 */
const digestOf = (authorization: string | null): string =>
  authorization === null
    ? "absent"
    : createHash("sha256").update(authorization, "utf8").digest("hex");

/**
 * The verified identity for this request, or null when the caller is a
 * visitor. This and {@link kindOf} / {@link actorOf} / {@link hasScope} are
 * the **only** supported accessors: the value is held in a module-private
 * WeakMap keyed on the response, so there is no key on `res.locals` to read
 * instead and nothing of ours appears in an inspection of it.
 *
 * There is deliberately no second copy of `kind` or of the subject. One source
 * of truth — the center's answer — and these four read it.
 */
export const identityOf = (res: ResponseLike): Identity | null =>
  requestState.get(res)?.identity ?? null;

/**
 * The subject, or null for a visitor. This is the accessor for
 * automation-service's `detail.actor` recording, which used to read a
 * `res.locals.actor` string key.
 */
export const actorOf = (res: ResponseLike): string | null =>
  identityOf(res)?.sub ?? null;

/**
 * The center's `kind`, or null for a visitor. Never derived from the subject:
 * a fence written as `kindOf(res) === "machine"` is the supported spelling.
 */
export const kindOf = (res: ResponseLike): Kind | null =>
  identityOf(res)?.kind ?? null;

/** True when this request carries a verified session holding `scope`. */
export const hasScope = (res: ResponseLike, scope: string): boolean =>
  identityOf(res)?.scopes.includes(scope) ?? false;

/**
 * What {@link requirementOf} reports for a route declared
 * {@link ExpressAuth.ignoreCredentials}. Reserved: `requireScope()` and a
 * fixed `guard()` refuse it, and a resolver returning it is undeclared, so it
 * never means anything else.
 */
export const CREDENTIALS_IGNORED = "ignore-credentials";

/** A {@link RouteRequirement}, or a route that declared it never reads identity. */
export type DeclaredRequirement = RouteRequirement | typeof CREDENTIALS_IGNORED;

/** What the route this request matched declared, or null if it declared nothing. */
export const requirementOf = (res: ResponseLike): DeclaredRequirement | null =>
  requestState.get(res)?.requires ?? null;

/**
 * Maps one request to what its route declares, from the **method alone**.
 *
 * Returning `undefined` means **undeclared**, which is a `500` on every
 * method. It is not `"none"`, and there is deliberately no way to spell "I
 * could not find this route, serve it anyway".
 */
export type RequirementResolver = (
  context: GuardContext
) => RouteRequirement | undefined;

/**
 * Everything a resolver is given.
 *
 * Deliberately one field. On a `HEAD` it reads `"GET"`, because `HEAD /x` is
 * the same route as `GET /x` and Express dispatches it to that handler; the
 * real `req.method` is untouched, so the request is still answered as a `HEAD`.
 */
export interface GuardContext {
  readonly method: string;
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/*
 * What a handler is, recorded outside the handler.
 *
 * WeakMaps rather than a property on the function, so nothing this package is
 * handed is mutated — a frozen middleware, or one shared with another library,
 * is none of our business. It is also why a brand cannot be forged: there is
 * no `h.__declares` for a caller to set, and an object this package never
 * branded is not in the map however it is shaped.
 *
 * These are module-scoped, which assumes one copy of this package per process.
 * That is true for the three consumers (each installs one tarball) and, if it
 * ever stopped being true, `secured()` would not recognise the other copy's
 * declarations and would refuse to start — the loudest possible way for that
 * to surface.
 */

/** Handlers that carry a route declaration, and what they declare. */
const declarations = new WeakMap<object, DeclaredRequirement>();
/** Router-level guards: a blanket declaration for everything behind them. */
const guards = new WeakSet<object>();
/**
 * The subset of {@link declarations} made by `ignoreCredentials()`, which are
 * accepted only where every method the registration covers is safe.
 */
const credentialIgnorers = new WeakSet<object>();
/** Handlers a caller has explicitly vouched for as not being a route. */
const passthroughs = new WeakSet<object>();
/** Terminal not-found handlers: they serve no resource, so they declare none. */
const terminals = new WeakSet<object>();
/** Routers, apps and routes already wrapped by {@link secured}. */
const securedTargets = new WeakSet<object>();

/** Both spellings of "this handler decides whether the request may proceed". */
const isDeclaration = (value: unknown): boolean =>
  typeof value === "function" &&
  (declarations.has(value) || guards.has(value));

const isBranded = (set: WeakSet<object>, value: unknown): boolean =>
  typeof value === "function" && set.has(value);

/**
 * Vouch for a handler that **never serves a resource**: a body parser, a CORS
 * middleware, a logger — anything that will call `next()` rather than answer a
 * request for something.
 *
 * "Never serves a resource" rather than "never responds": a `cors()` that
 * terminates a preflight is a passthrough, because a preflight asks for
 * permission rather than for a resource, and an OPTIONS answered with headers
 * discloses nothing a route would have protected. Anything that can answer a
 * request *for something* is a route and declares like one.
 *
 * From the outside a middleware and a route are the same shape and only the
 * author knows which one will answer, so this is the explicit way to say
 * which it is. `why` is required so the escape hatch reads as a decision in
 * the diff rather than as a cast.
 *
 * ```ts
 * api.use(passthrough(express.json(), "parses bodies; never answers"));
 * ```
 *
 * "Never answers" is the whole claim: a `cors()` that terminates a preflight
 * is still a passthrough, because a preflight is not a resource. Anything that
 * can serve one is a route and declares.
 *
 * What comes back is a **wrapper**, branded in this package's place of the
 * caller's function: branding the argument would leave the caller holding a
 * vouched-for function it could then register anywhere, undeclared. The
 * wrapper delegates with the same `this` and arguments and reports the same
 * `length`, which is how Express tells an error handler from an ordinary one.
 */
export function passthrough<H>(handler: H, why: string): H {
  if (typeof handler !== "function") {
    throw new TypeError("passthrough() takes a middleware function");
  }
  if (typeof why !== "string" || why.trim().length === 0) {
    throw new TypeError(
      "passthrough() requires a reason: say why this handler is not a route that needs a declaration"
    );
  }
  const wrapper = delegating(handler as unknown as (...a: unknown[]) => unknown);
  passthroughs.add(wrapper);
  return wrapper as unknown as H;
}

/**
 * A function that calls `fn` and reports `fn`'s arity.
 *
 * `Function.prototype.length` is `configurable: true`, so it can be redefined;
 * Express reads it at dispatch time to decide whether a layer is an error
 * handler, and a wrapper that reported 3 where the original said 4 would turn
 * an error handler into one that runs on ordinary requests.
 */
const delegating = (
  fn: (...args: unknown[]) => unknown
): ((...args: unknown[]) => unknown) => {
  const wrapper = function (this: unknown, ...args: unknown[]): unknown {
    return fn.apply(this, args);
  };
  Object.defineProperty(wrapper, "length", {
    value: fn.length,
    configurable: true,
  });
  return wrapper;
};

/**
 * The terminal "nothing matched" handler, which needs no credential because
 * it serves no resource.
 *
 * ```ts
 * app.use(notFound((_req, res) => res.status(404).json({ error: { message: "not found" } })));
 * ```
 *
 * It is accepted in **exactly one position**: `use(notFound(handler))` — no
 * path argument, the only handler of that call, never on `get`/`post`/`all`
 * or a `route()` chain, and last, so that only an error handler (arity 4) may
 * follow. Every other position is a general catch-all wearing a 404's clothes:
 * `app.use("/admin", notFound(h))` would serve `h` to anyone for every method
 * under `/admin`, with nothing declared and no call to the center. That was a
 * real hole here, and the position rule is half of closing it.
 *
 * The other half is that what comes back is a **wrapper that cannot answer a
 * success**. It sets `404` before calling the handler, refuses any attempt to
 * set a status below `400` while it runs, and forces `404` again afterwards if
 * the status somehow came back under `400` and the head has not gone out. A
 * "not found" that can be made to return `200` is just an undeclared route.
 *
 * The brand goes on the wrapper, never on the caller's function: branding the
 * argument would hand the caller a vouched-for function to register anywhere.
 *
 * It is not an authorization decision and does not ask the center: a 404 that
 * introspected first would tell an unauthenticated caller the difference
 * between a route that exists and one that does not, and would put the center
 * on the path of every mistyped URL.
 */
export function notFound<H>(handler: H): H {
  if (typeof handler !== "function") {
    throw new TypeError("notFound() takes a handler function");
  }
  const inner = handler as unknown as HandlerLike;

  const wrapper: HandlerLike = (req, res, next) => {
    const setStatus = res.status.bind(res) as (code: number) => ResponseLike;
    const mutable = res as unknown as Record<string, unknown>;
    const hadOwnStatus = Object.prototype.hasOwnProperty.call(res, "status");
    const ownStatus = mutable["status"];
    let restored = false;
    const restore = (): void => {
      if (restored) return;
      restored = true;
      if (hadOwnStatus) mutable["status"] = ownStatus;
      else delete mutable["status"];
    };

    setStatus(404);
    // While the terminal runs, `res.status(200)` is a defect rather than an
    // instruction. Clamped rather than thrown: the caller gets its 404 and the
    // request still ends, which is the safe reading of a handler that has
    // already been told it is answering "not found".
    mutable["status"] = (code: unknown): ResponseLike =>
      setStatus(typeof code === "number" && code >= 400 ? code : 404);

    try {
      inner(req, res, (err?: unknown) => {
        // Handing control on: the response is no longer ours to clamp, and an
        // error handler must be able to answer 500.
        restore();
        next(err);
      });
    } finally {
      if (!restored) {
        const current = res.statusCode;
        if (
          typeof current === "number" &&
          current < 400 &&
          res.headersSent !== true
        ) {
          setStatus(404);
        }
      }
    }
  };

  terminals.add(wrapper);
  return wrapper as unknown as H;
}

// ---------------------------------------------------------------------------
// secured()
// ---------------------------------------------------------------------------

/**
 * Every method name Express can register a route under.
 *
 * Taken from Node's own list — which is where Express's `methods` dependency
 * gets it too — rather than from a hand-written set of the seven anybody
 * remembers. A hand-written set is a hole shaped like `router.trace(...)`.
 */
const ROUTE_METHODS: readonly string[] = [
  ...new Set([...METHODS.map((m) => m.toLowerCase()), "delete", "all"]),
];

const HOW_TO_DECLARE = [
  "Every route must say what it needs, as its FIRST handler:",
  "",
  "    auth.ignoreCredentials()           — never reads identity: health, docs, static files",
  "    auth.allowPublic()                 — anyone; a presented bearer is still verified",
  "    auth.requireSession()              — any verified session",
  '    auth.requireScope("fleet:control") — a session carrying that scope',
  "",
  "If this handler is middleware rather than a route — a body parser, CORS, a",
  'logger — wrap it: passthrough(handler, "why it never answers").',
  "",
  "If it is the terminal not-found handler, wrap it: notFound(handler).",
].join("\n");

const flattenHandlers = (values: readonly unknown[]): unknown[] => {
  const out: unknown[] = [];
  for (const value of values) {
    if (Array.isArray(value)) out.push(...flattenHandlers(value));
    else out.push(value);
  }
  return out;
};

/** The leading path/pattern argument Express accepts, which is not a handler. */
const isPathArgument = (value: unknown): boolean =>
  typeof value === "string" ||
  value instanceof RegExp ||
  (Array.isArray(value) && value.length > 0 && value.every(isPathArgument));

const describePath = (value: unknown): string =>
  isPathArgument(value) ? String(value) : "<no path>";

/**
 * The handler list, with Express's leading path argument removed.
 *
 * Only argument 0 can be a path — `app.get(path, ...handlers)` — so a string
 * later in the list is a mistake rather than a second path, and is left in to
 * be refused as an unbranded handler.
 */
const handlerList = (args: readonly unknown[]): unknown[] =>
  flattenHandlers(isPathArgument(args[0]) ? args.slice(1) : args);

/** Per-secured-target bookkeeping that a single call cannot see. */
interface SecuredState {
  /** A `notFound()` has been mounted; only error handlers may follow. */
  terminated: boolean;
  /**
   * For a `route()` chain only: the methods that already carry a declaration.
   * `router.route("/x").get(decl, h).get(more)` is two calls building one
   * route, so "first handler of the route" is a property of the chain rather
   * than of the call.
   */
  readonly declaredMethods: Set<string>;
  /** True for a `route()` chain, false for a router or an app. */
  readonly isRoute: boolean;
}

/**
 * Refuse, at startup, to register a route whose first handler is not a
 * declaration — or that carries two.
 *
 * `label` is the method the call came in on, used in the message and, for a
 * `route()` chain, as the key the chain's declaration is remembered under.
 * The throw is deliberately an `Error` at require/boot time: a service that
 * cannot say what one of its routes needs must not start, because the
 * alternative is that it starts and serves it.
 */
const assertRouteDeclared = (
  label: string,
  args: readonly unknown[],
  name: string,
  state: SecuredState
): void => {
  const where = `${name}.${label}(${describePath(args[0])})`;
  const handlers = handlerList(args);
  const declared = handlers.filter(isDeclaration).length;

  // On a route() chain, `.all()` covers every method, so a declaration there
  // is the route's declaration whatever method comes next.
  const alreadyDeclared =
    state.isRoute &&
    (state.declaredMethods.has(label) || state.declaredMethods.has("all"));

  if (declared > 1 || (declared > 0 && alreadyDeclared)) {
    throw new Error(
      `${where} was registered with more than one authorization declaration.\n\n` +
        "A route declares its requirement exactly once. Two declarations are two\n" +
        "answers to reconcile and two calls to the center for one request; if a\n" +
        "route needs both a session and a scope, requireScope() already implies\n" +
        "the session."
    );
  }

  if (alreadyDeclared) return;

  // Only a vouched-for passthrough may precede the declaration. Anything else
  // is a handler that runs — and can answer — before anything authorized it.
  let index = 0;
  while (index < handlers.length && isBranded(passthroughs, handlers[index])) {
    index += 1;
  }

  if (declared === 0) {
    throw new Error(
      `${where} was registered without an authorization declaration.\n\n` +
        HOW_TO_DECLARE
    );
  }
  if (!isDeclaration(handlers[index])) {
    throw new Error(
      `${where} was registered with a handler before its authorization declaration.\n\n` +
        "Express runs a route's handlers in registration order, so a handler\n" +
        "ahead of the declaration has already answered by the time anything\n" +
        "checks a credential. Put the declaration first:\n\n" +
        `    ${name}.${label}(${describePath(args[0])}, auth.requireScope("…"), handler)\n\n` +
        "A middleware that genuinely never answers may precede it, once it says\n" +
        'so: passthrough(handler, "why it never answers").'
    );
  }

  state.declaredMethods.add(label);
};

/**
 * Route registrations `ignoreCredentials()` may lead: the ones whose every
 * method is safe. An allowlist, so `all`, `trace`, `propfind` and whatever
 * Node adds next are refused rather than audited.
 */
const IGNORE_CREDENTIALS_METHODS: ReadonlySet<string> = new Set([
  "get",
  "head",
  "options",
]);

/**
 * Refuse `ignoreCredentials()` on a registration that covers a mutating method.
 *
 * A mutation that reads no credential is the same defect `allowPublic()`
 * answers 500 for; here it is caught before the process starts. Checked
 * before the positional rules so the message names the real mistake.
 */
const assertIgnoreOnSafeMethod = (
  method: string,
  args: readonly unknown[],
  name: string
): void => {
  if (IGNORE_CREDENTIALS_METHODS.has(method)) return;
  if (!handlerList(args).some((h) => isBranded(credentialIgnorers, h))) return;
  throw new Error(
    `${name}.${method}(${describePath(args[0])}) was registered with ignoreCredentials().\n\n` +
      "ignoreCredentials() is accepted only on get, head and options routes and on\n" +
      "use() mounts, because a mutation that reads no credential is a defect, not\n" +
      "a policy. A mutating route declares what it needs:\n\n" +
      `    ${name}.${method}(${describePath(args[0])}, auth.requireScope("…"), handler)`
  );
};

/**
 * The same, for `use()`, which mounts more than routes.
 *
 * A `use()` is a **declared mount** when a declaration leads it: the
 * declaration covers every handler after it, which is the construct all three
 * consumers actually have —
 * `app.use("/proxy", auth.requireSession(), express.raw(…), proxy)`,
 * `app.use("/swagger", auth.allowPublic(), swaggerUi.serve, swaggerUi.setup(spec))`,
 * `app.use("/assets", auth.allowPublic(), express.static(dir))`. The
 * first-position rule is the same as a route's, for the same reason.
 *
 * Without a declaration, every item must vouch for itself: a `passthrough()`,
 * a nested `secured()` router, a `notFound()`, or an error handler.
 */
const assertUseSafe = (args: readonly unknown[], name: string): void => {
  const where = `${name}.use(${describePath(args[0])})`;
  const handlers = handlerList(args);
  const declared = handlers.filter(isDeclaration).length;

  if (declared > 1) {
    throw new Error(
      `${where} was given more than one authorization declaration.\n\n` +
        "A mount declares its requirement exactly once: the leading declaration\n" +
        "covers everything after it."
    );
  }

  const terminalIndex = handlers.findIndex((h) => isBranded(terminals, h));
  if (terminalIndex >= 0) {
    if (terminalIndex !== handlers.length - 1) {
      throw new Error(
        `${where} mounts a notFound() handler with handlers after it.\n\n` +
          "A terminal not-found handler answers everything that reaches it, so\n" +
          "anything registered behind it is unreachable. It goes last."
      );
    }
    // The only accepted spelling. A path argument, or another handler in the
    // same call, turns the terminal into a catch-all for everything under that
    // path: it answers every method, declares nothing and never asks the
    // center, which is an authorization bypass wearing a 404's clothes.
    if (isPathArgument(args[0]) || handlers.length !== 1) {
      throw new Error(
        `${where} mounts a notFound() handler on a path or alongside other handlers.\n\n` +
          "A notFound() terminal is accepted in exactly one position:\n\n" +
          "    app.use(notFound(handler));\n\n" +
          "with no path argument and no other handler in the call. Mounted on a\n" +
          "path it is a catch-all that answers every method under that path with\n" +
          "no declaration and no call to the center. If that mount is meant to\n" +
          "serve something, it is a route and declares like one:\n\n" +
          '    app.use("/admin", auth.requireScope("…"), handler);'
      );
    }
  }

  if (declared === 1) {
    let index = 0;
    while (index < handlers.length && isBranded(passthroughs, handlers[index])) {
      index += 1;
    }
    if (!isDeclaration(handlers[index])) {
      throw new Error(
        `${where} was given a handler before its authorization declaration.\n\n` +
          "A declared mount puts the declaration first; everything after it is\n" +
          "covered by it:\n\n" +
          `    ${name}.use(${describePath(args[0])}, auth.requireSession(), express.raw(…), handler)\n`
      );
    }
    return;
  }

  for (const item of handlers) {
    if (isBranded(passthroughs, item)) continue;
    if (isBranded(terminals, item)) continue;
    // An express.Router() is a function; a nested secured app or route is an
    // object. Either way it enforces the rule for everything inside it.
    if (typeof item === "function" && securedTargets.has(item)) continue;
    if (typeof item === "object" && item !== null && securedTargets.has(item)) {
      continue;
    }
    // Arity 4 is Express's error-handler signature, and Express invokes such a
    // layer ONLY while an error is already in flight — never as the layer that
    // answers an ordinary request. It therefore cannot be the thing that
    // serves an undeclared route, and requiring a declaration on it would
    // require a credential to render a 500.
    if (typeof item === "function" && item.length >= 4) continue;

    throw new Error(
      `${where} was given a handler that is neither a declaration nor a vouched-for middleware.\n\n` +
        HOW_TO_DECLARE +
        "\n\nA nested router is fine too, as long as it is itself secured():\n" +
        '\n    api.use("/ships", secured(express.Router()));\n'
    );
  }
};

/** Nothing may be registered after a `notFound()` except an error handler. */
const assertNotTerminated = (
  state: SecuredState,
  where: string,
  args: readonly unknown[],
  isUse: boolean
): void => {
  if (!state.terminated) return;
  const handlers = handlerList(args);
  const onlyErrorHandlers =
    isUse &&
    handlers.length > 0 &&
    handlers.every((h) => typeof h === "function" && h.length >= 4);
  if (onlyErrorHandlers) return;
  throw new Error(
    `${where} was registered after a notFound() handler.\n\n` +
      "The terminal not-found handler answers everything that reaches it, so\n" +
      "this would never run. Register it before the notFound(); only an error\n" +
      "handler (arity 4) belongs after one."
  );
};

/**
 * Make an Express router, app or route refuse, **at registration time**, to
 * register a handler that carries no authorization declaration, or that puts
 * one anywhere but first.
 *
 * ```ts
 * const api = secured(express.Router());
 * api.get("/ships", auth.requireSession(), listShips);   // fine
 * api.get("/ships", listShips);                          // throws at startup
 * api.get("/ships", listShips, auth.requireSession());   // throws at startup
 * ```
 *
 * This is the backstop that cannot be forgotten, and it is a *startup* failure
 * rather than a per-request one: an undeclared route does not exist, instead
 * of existing and being caught the first time somebody asks for it.
 *
 * The target is patched **in place** and returned, so `app.use("/api", api)`,
 * nesting, `route()` chaining and any reference taken before or after the call
 * all go through the patched methods. Calling it twice on the same target does
 * nothing the second time.
 *
 * **What it does not cover** is listed in the README under "What this package
 * does not protect", because a fence whose gaps are unknown is worse than no
 * fence.
 */
export function secured<T extends object>(target: T): T {
  return secureTarget(target, false);
}

function secureTarget<T extends object>(target: T, isRoute: boolean): T {
  if (securedTargets.has(target)) return target;
  securedTargets.add(target);
  const state: SecuredState = {
    terminated: false,
    declaredMethods: new Set<string>(),
    isRoute,
  };

  const record = target as unknown as Record<string, unknown>;
  const name = targetName(record, isRoute);

  for (const method of ROUTE_METHODS) {
    const original = record[method];
    if (typeof original !== "function") continue;
    const call = original.bind(target) as (...args: unknown[]) => unknown;
    record[method] = (...args: unknown[]): unknown => {
      // `app.get("view engine")` is Express's settings GETTER, not a route.
      // One string argument and nothing else is unambiguously that: a route
      // with a path and no handler at all is not a route either.
      if (method === "get" && args.length === 1 && typeof args[0] === "string") {
        return call(...args);
      }
      assertNotTerminated(
        state,
        `${name}.${method}(${describePath(args[0])})`,
        args,
        false
      );
      // Order is load-bearing: `post("/x", requireSession(), ignore, h)`
      // is two declarations AND ignoreCredentials() on a mutation, and the
      // message must name the mutation rule — the fix is to drop the
      // ignoreCredentials(), not to pick one of two equals.
      assertIgnoreOnSafeMethod(method, args, name);
      assertRouteDeclared(method, args, name, state);
      return call(...args);
    };
  }

  // Express 4's deprecated `app.del` is `deprecate.function(app.delete)`:
  // it holds the ORIGINAL `delete`, captured when Express loaded, so the
  // patch above never sees a call made through it and `app.del("/d", h)`
  // registered and served an undeclared DELETE. Refused rather than
  // forwarded: a deprecated spelling of a mutating method has no caller worth
  // keeping, and one route method with two spellings is one more thing to
  // audit. Installed on routers and routes too, which have no `del` of their
  // own, so the spelling means the same thing on every secured target.
  record["del"] = (...args: unknown[]): never => {
    throw new Error(
      `${name}.del(${describePath(args[0])}) is Express 4's deprecated alias for delete(), and is refused.\n\n` +
        "It calls the delete() Express captured when it loaded, not the one\n" +
        "secured() checks, so a route registered through it would carry no\n" +
        "declaration check at all. Use delete(...):\n\n" +
        `    ${name}.delete(${describePath(args[0])}, auth.requireScope("…"), handler)`
    );
  };

  const originalUse = record["use"];
  if (typeof originalUse === "function") {
    const call = originalUse.bind(target) as (...args: unknown[]) => unknown;
    record["use"] = (...args: unknown[]): unknown => {
      const where = `${name}.use(${describePath(args[0])})`;
      assertNotTerminated(state, where, args, true);
      assertUseSafe(args, name);
      const result = call(...args);
      if (handlerList(args).some((h) => isBranded(terminals, h))) {
        state.terminated = true;
      }
      return result;
    };
  }

  // `router.route("/x").get(handler)` registers a route without going through
  // `router.get`, so the returned Route is secured too — otherwise it is a
  // hole in the shape of a chaining style somebody prefers.
  const originalRoute = record["route"];
  if (typeof originalRoute === "function") {
    const call = originalRoute.bind(target) as (...args: unknown[]) => unknown;
    record["route"] = (...args: unknown[]): unknown => {
      const route = call(...args);
      return typeof route === "object" && route !== null
        ? secureTarget(route as object, true)
        : route;
    };
  }

  return target;
}

/** What the error messages call this target. */
const targetName = (
  record: Record<string, unknown>,
  isRoute: boolean
): string => {
  if (isRoute) {
    return typeof record["path"] === "string"
      ? `route(${record["path"] as string})`
      : "route";
  }
  return typeof record["name"] === "string" && record["name"].length > 0
    ? (record["name"] as string)
    : "router";
};

export interface ExpressAuth {
  /**
   * Declare that a route needs a session carrying `scope`, and enforce it.
   * Attach it as the route's **first** handler:
   *
   * ```ts
   * api.post("/ships/:id/navigate", auth.requireScope("fleet:control"), navigate);
   * ```
   *
   * Express's own matcher binds this to the same route it binds the handler
   * to, so a mount prefix, a trailing slash, a case-variant path and a
   * parameter all resolve exactly as the route does — and a `HEAD` reaches the
   * `GET` route's declaration because Express dispatches it to that route.
   *
   * Throws at startup for `"none"`, `"session"` and `"ignore-credentials"`,
   * which are the reserved words for the other intents: `requireScope("none")`
   * reads as a demand and silently produced a **public** route.
   */
  requireScope(scope: string): HandlerLike;
  /** Any verified session, carrying any scopes at all, including none. */
  requireSession(): HandlerLike;
  /**
   * Declare a route **public**: an anonymous caller proceeds as a visitor on a
   * safe method, and a mutating method answers `500`, because a mutation that
   * needs no credential is a defect rather than a policy.
   *
   * This is the only way a route is public. A declaration nobody wrote is not
   * a public route, it is an undeclared one.
   */
  allowPublic(): HandlerLike;
  /**
   * Declare a route that **never reads identity**: health, API docs, static
   * files. The `Authorization` header is not read and the center is never
   * called, so a valid, expired or garbage bearer all get the same answer and
   * the route stays up while auth-service is down. `identityOf(res)` is null
   * and `requirementOf(res)` is {@link CREDENTIALS_IGNORED}.
   *
   * Contrast {@link allowPublic}, for reads whose answer depends on an
   * *optional* identity: there a presented bearer is verified, so an expired
   * one is a 401 and a down center a 503.
   *
   * Refused at registration on anything but `get`, `head`, `options` and
   * `use()`. A mutating method that still reaches it through a `use()` mount
   * answers `500` before any header is read.
   */
  ignoreCredentials(): HandlerLike;
  /**
   * Router-level middleware, for routes that cannot carry a declaration —
   * generated routers, chiefly. Mount once with `router.use(auth.guard(...))`.
   *
   * `resolve` is a fixed requirement or a function of `{ method }`. Returning
   * `undefined`, or throwing, means **undeclared**: `500` on every method,
   * before the header is read. There is no fallback to `"none"`.
   *
   * The method is all a resolver gets, deliberately: a `use`-mounted
   * middleware runs before any route layer matches, so there is no matched
   * route to ask and any path it reconstructed would be a second, worse
   * matcher. On a `HEAD` the method reads `"GET"`.
   */
  guard(resolve: RouteRequirement | RequirementResolver): HandlerLike;
}

/** Writes a rejection in the family's `{"error":{"message":…}}` envelope. */
const sendRejection = (
  res: ResponseLike,
  status: number,
  message: string
): void => {
  res.status(status).json({ error: { message } });
};

const apply = (res: ResponseLike, decision: Decision, next: NextLike): void => {
  if (decision.outcome === "reject") {
    sendRejection(res, decision.status, decision.message);
    return;
  }
  stateOf(res).identity = decision.identity;
  next();
};

export function createExpressAuth(
  source: IntrospectionConfig | Introspector | Authorizer
): ExpressAuth {
  /*
   * A request may pass through two enforcement points — a router-level
   * `guard()` and a route's own declaration — and each must be checked, so
   * the stricter effectively wins. What must NOT happen twice is the HTTP
   * call: one inbound request is one question for the center.
   *
   * The answer is memoized in a module-private WeakMap keyed on the RESPONSE
   * object, so it lives exactly as long as the response does and cannot be
   * shared between requests — a process-wide cache keyed on the header would
   * be a second verification path with a different answer, would make
   * revocation meaningless for its lifetime, and would hand one caller's
   * identity to another the moment two callers presented the same header
   * value.
   *
   * It is keyed on a SHA-256 DIGEST of the `Authorization` header as well, so
   * a second enforcement point reading a header the first did not see asks
   * again rather than reusing an answer about a different credential — and so
   * that the memo never holds the credential itself.
   */
  let injected: Authorizer | null = null;
  let introspector: Introspector | null = null;
  if ("authorize" in source) injected = source;
  else if ("introspect" in source) introspector = source;
  else introspector = createIntrospector(source);

  const authorizerFor = (
    res: ResponseLike,
    authorization: string | null
  ): Authorizer => {
    // A host that injected a whole Authorizer keeps its own transport, and
    // there is no introspector here to memoize around.
    if (injected !== null) return injected;
    const state = stateOf(res);
    const digest = digestOf(authorization);
    return createAuthorizer({
      introspect: (token) => {
        const memo = state.memo;
        if (memo !== undefined && memo.digest === digest) return memo.answer;
        const answer = introspector!.introspect(token);
        state.memo = { digest, answer };
        return answer;
      },
    });
  };

  const handlerFor = (resolve: RequirementResolver): HandlerLike => {
    return (req, res, next) => {
      let requires: RouteRequirement | undefined;
      try {
        const method = req.method.toUpperCase() === "HEAD" ? "GET" : req.method;
        requires = resolve({ method });
      } catch {
        requires = undefined;
      }
      // The reserved word is a declaration, not resolver vocabulary. Read as
      // a scope it would be enforced as one while `requirementOf` reported
      // the opposite, so it is undeclared instead.
      if (requires === CREDENTIALS_IGNORED) requires = undefined;

      if (requires === undefined) {
        // Undeclared. A resolver that threw has told us nothing about this
        // route; a resolver that returned `undefined` has told us it could
        // not find it. Both are the same class of defect — ours — and both
        // fail closed on EVERY method, safe ones included. A fallback to
        // `"none"` would make a miss indistinguishable from a route that
        // declared itself public; `"session"` would serve the route to anyone
        // holding any token at all. Neither is a thing to guess.
        stateOf(res).requires = null;
        sendRejection(res, 500, MESSAGES.undeclaredRoute);
        return;
      }
      stateOf(res).requires = requires;

      // The one place every declaration and every guard reads the header,
      // so the line-count rule is the same for all of them.
      const authorization = credentialOf(req);

      authorizerFor(res, authorization)
        .authorize({ method: req.method, requires, authorization })
        .then((decision) => apply(res, decision, next))
        // The authorizer is written not to reject; if a host's injected
        // introspector does, the request must still fail closed rather than
        // hand Express an unhandled promise. `next(err)` and not `next()`:
        // passing no error would run the handler the guard just failed to
        // authorize.
        .catch(() => next(new Error("introspection failed")));
    };
  };

  /** A handler that declares `requires`, branded so `secured()` can see it. */
  const declaring = (requires: RouteRequirement): HandlerLike => {
    const handler = handlerFor(() => requires);
    declarations.set(handler, requires);
    return handler;
  };

  /**
   * The `ignoreCredentials()` handler. It reads `req.method` and nothing else
   * of the request: no header, no center, no memo.
   */
  const ignoring = (): HandlerLike => {
    const handler: HandlerLike = (req, res, next) => {
      const state = stateOf(res);
      state.requires = CREDENTIALS_IGNORED;
      // Even if an outer guard verified someone, this route declared it does
      // not read identity, so it is handed none — on the 500 below as well,
      // where an error handler or a `finish` listener may still ask.
      state.identity = null;
      if (!isSafeMethod(req.method)) {
        // Registration refuses this on a mutating route; a `use()` mount
        // still sees every method. Same answer as `allowPublic()` gives,
        // decided before any header is read.
        sendRejection(res, 500, MESSAGES.undeclaredRoute);
        return;
      }
      next();
    };
    declarations.set(handler, CREDENTIALS_IGNORED);
    credentialIgnorers.add(handler);
    return handler;
  };

  const RESERVED_HELP =
    "    a route that never reads identity — auth.ignoreCredentials()\n" +
    "    a public route                    — auth.allowPublic()\n" +
    "    any verified session              — auth.requireSession()\n\n";

  return {
    requireScope: (scope) => {
      if (typeof scope !== "string" || scope.trim().length === 0) {
        throw new TypeError(
          "requireScope() takes a scope literal, such as requireScope(\"fleet:control\")"
        );
      }
      if (scope === "none" || scope === "session" || scope === CREDENTIALS_IGNORED) {
        throw new TypeError(
          `requireScope("${scope}") is not a scope: "${scope}" is reserved.\n\n` +
            RESERVED_HELP +
            "Spelled as a scope it read as a demand and silently produced the " +
            "opposite."
        );
      }
      return declaring(scope);
    },
    requireSession: () => declaring("session"),
    allowPublic: () => declaring("none"),
    ignoreCredentials: ignoring,
    guard: (resolve) => {
      if (resolve === CREDENTIALS_IGNORED) {
        throw new TypeError(
          `guard("${CREDENTIALS_IGNORED}") is not a requirement: it is reserved.\n\n` +
            RESERVED_HELP
        );
      }
      const handler = handlerFor(
        typeof resolve === "function" ? resolve : () => resolve
      );
      guards.add(handler);
      return handler;
    },
  };
}

/**
 * The `Authorization` value this request may be authorized on, or null for
 * **no credential**.
 *
 * Node's parser keeps the first `Authorization` line and discards any repeat,
 * so `req.header("Authorization")` for `Bearer a` + `Bearer b` is `"Bearer a"`,
 * and for an empty line + `Bearer b` it is `""`. Read on its own, that lets the
 * caller choose which of two credentials is verified, or turn a credentialed
 * request into a visitor. The spec's answer is that two lines are never a
 * credential, whatever they hold — so the lines are counted in `rawHeaders`,
 * the only place the repeat survives, and more than one is null: a `401 a
 * bearer token is required` where a session is needed, a visitor on a public
 * read, and no call to the center either way.
 *
 * A request with no `rawHeaders` array cannot be counted, and is read as no
 * credential rather than trusted to have sent one line.
 *
 * With exactly one line the value still comes from `header()`, as it always
 * has; a comma-folded value carrying two credentials is then read by
 * `bearerFrom` as none.
 */
const credentialOf = (req: RequestLike): string | null => {
  if (!Array.isArray(req.rawHeaders)) return null;
  if (authorizationLines(req.rawHeaders) > 1) return null;
  return headerValue(req, "Authorization");
};

/** One header as a single string, or null. An array is joined as Node joins. */
const headerValue = (req: RequestLike, name: string): string | null => {
  const value = req.header(name);
  if (value === undefined) return null;
  return Array.isArray(value) ? value.join(", ") : value;
};
