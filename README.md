# @v-m-pioneer-trading/introspection-client

The TypeScript half of "one verifier". [auth-design decision 21][d21] makes
auth-service the only component that verifies a token; everyone else asks it
what the token carries and compares the answer against what their own route
declared. This package is that client for the three Node services
(fleet-service, automation-service, st-gateway).

Its behaviour is not described here but *fixed* by
[`fixtures/introspection.json`][fixture] in `meta` — thirty-seven conditions for
a calling service and eleven for st-gateway's queue lane, each with the center's
response and the exact status, message, identity and call count expected. It is
vendored into `test/fixtures/`, and the conformance suite drives all forty-eight
cases against a real local HTTP stub.

Zero runtime dependencies and **no peer dependencies at all** — not even
Express, whose types are declared locally, so a consumer with
`skipLibCheck: false` and no `@types/express` typechecks this package with
nothing installed. CommonJS plus `.d.ts`, Node >= 18. There is no registry: a
`v*` tag attaches the tarball to a GitHub Release and consumers install that
URL, which `package-lock.json` records with an integrity hash, so the Docker
build needs no token and no git.

```sh
npm install https://github.com/V-M-Pioneer-Trading/ts-introspection-client/releases/download/v1.1.1/v-m-pioneer-trading-introspection-client-1.1.1.tgz
```

## Quick start

```ts
import express from "express";
import {
  actorOf,
  createExpressAuth,
  loadIntrospectionConfig,
  notFound,
  secured,
} from "@v-m-pioneer-trading/introspection-client";

const auth = createExpressAuth(loadIntrospectionConfig()); // throws, naming a missing env var
const app = secured(express());
const api = secured(express.Router());

api.get("/health", auth.ignoreCredentials(), (_req, res) => res.json({ status: "ok" }));
api.get("/targets", auth.requireSession(), listTargets);
api.post("/targets", auth.requireScope("fleet:control"), (req, res) =>
  res.json({ by: actorOf(res) })
);

app.use("/api/automation/v1", api);
app.use(notFound((_req, res) => res.status(404).json({ error: { message: "not found" } })));
```

The declaration is the route's **first** handler. Leave it off, put it second,
or write two, and the process does not start, with a message naming the route
and listing the spellings:

| Declaration | `Authorization` header | Center | Mutating methods |
|---|---|---|---|
| `ignoreCredentials()` | never read; identity `null` | never called | refused at registration; `500` via a `use()` mount |
| `allowPublic()` | optional; if presented, verified | called when a bearer is presented | `500` |
| `requireSession()` | required | called | enforced |
| `requireScope(scope)` | required, session must carry `scope` | called | enforced |

`ignoreCredentials()` is for routes that never read identity (health, API
docs, static files); `allowPublic()` is for reads whose answer depends on an
optional identity. They differ because `allowPublic()` verifies a bearer it is
shown, so an expired token is a `401` and a down center a `503` even on a
public page, which is right for a personalised read and wrong for a health
check.

## Security model

**P1. A route with no declaration is never served — on any method, including
`GET`, `HEAD` and `OPTIONS`.** "Public" is a thing a route says out loud with
`allowPublic()` or `ignoreCredentials()`, never a thing that happens because
a lookup missed. A `guard()` resolver returning `undefined` or throwing is
*undeclared*, which is `500 this route declares no required scope`, decided
before the `Authorization` header is read and without calling the center. There is no fallback to
`"none"`.

> This is an **adapter** rule about a missing declaration, not the fixture's
> `requires: "none"`, which is a route that *declared* no credential is needed.
> "Undeclared" has no representation in the fixture at all.

**P2. Route matching is Express's job.** Declarations live at registration, so
Express's own matcher binds a requirement to the same route it binds the
handler to: a prefix-mounted router, a trailing slash, a case-variant path and
a `:parameter` never become a string this package looks up. A `guard()`
resolver is handed `{ method }` and nothing else for the same reason — inside a
`use` mount no route has matched yet, so any path it reconstructed would be a
second, worse matcher.

**P3. Position is part of the declaration, and there is exactly one.** Express
runs a route's handlers in registration order, so a declaration behind a
handler is a handler that already answered. Only a `passthrough()` may precede
one. Two declarations are refused outright.

**P4. A declared requirement is enforced for every method Express dispatches to
the route.** `HEAD` reaches its `GET` route's declaration because Express
dispatches it there, so a credential-free `HEAD` on a guarded route is the same
`401` as a `GET`; an `app.all` route answers `OPTIONS` with the real handler,
so its declaration governs that too. The safe methods are exempt from
**default-deny** — a route that declared `"none"` serves them to a visitor —
and from nothing else. An `OPTIONS` whose path matches but whose method does
not is answered by Express itself, before any layer on the route runs; see the
disclosure below.

**P5. CORS preflight works because `cors()` terminates it**, not because the
guard waves it through, so **mount `cors()` first**. Mounted after, an Express
router answers the preflight itself with a `200`, an `Allow` header and no
`Access-Control-Allow-Origin`, and the browser fails it. A test pins both
orders, so the remedy is known to be the mount order rather than an exemption
for `OPTIONS`.

**P6. One inbound request asks the center at most once.** A router-level
`guard()` and a route's own declaration both enforce — the stricter effectively
wins, because each compares the same answer against its own requirement — but
the answer is memoized for the life of the response, in a module-private
`WeakMap` keyed on the response object, under a **SHA-256 digest** of the
`Authorization` header. Nothing of ours is a property of `res` or of
`res.locals`, so none of it reaches `util.inspect(res.locals)`, a
`console.log`, a debugger or an error reporter — an earlier revision kept the
memo on `res.locals` together with the raw header it was about, which put a
live credential one `console.log` from a log aggregator. The digest is what
makes a second enforcement point reading a *different* header ask again rather
than reuse an answer about another credential. It is never shared between
requests: a process-wide cache would be a second verification path, would make
revocation meaningless for its lifetime, and would hand one caller's identity
to the next caller presenting the same header.

**P7. Two `Authorization` lines are never a credential**, whatever they hold.
Node's parser keeps the *first* `Authorization` line and discards the rest, so
`req.header("Authorization")` for `Bearer a` + `Bearer b` is `"Bearer a"` and
for an empty line + `Bearer b` it is `""`. Read alone, that lets a caller
choose which of two credentials is verified by choosing their order, or turn a
credentialed request into a visitor. The adapter therefore counts the lines in
`req.rawHeaders` — the only place the repeat survives, names compared
case-insensitively — and more than one is *no credential*: `401 a bearer token
is required` where a session or scope is declared, a visitor on an
`allowPublic()` read, and no call to the center either way. It is counted where
the header is read, once for every `requireScope`, `requireSession`,
`allowPublic` and `guard`; `ignoreCredentials()` reads neither. Anything that
is not the adapter — `createAuthorizer`, `createLaneDeriver` — takes a header
*value* and cannot see the count, so its caller applies the rule; see
[Two `Authorization` lines](#two-authorization-lines--outside-the-adapter).

### What this package does **not** protect

A fence whose gaps are unknown is worse than no fence.

- **Anything mounted before the guard or the secured router.** It answers
  without ever reaching them. A body parser is fine there; a route is not.
- **Handlers registered on an app or router that was never `secured()`.**
  (A reference taken *before* `secured()` is fine: it patches in place, so
  every alias goes through the patched methods.)
- **A Route obtained around the patch** — `Object.getPrototypeOf(router).route
  .call(router, "/x").get(handler)` — a layer pushed straight onto
  `router.stack`, and a route registered on an app's private `app._router`.
  All three reach Express's internals without passing through any method this
  package replaced. Closing them would mean mutating Express's own prototypes.
  Express 4's public alias `app.del()` — which calls the `delete` Express
  captured at load, not the patched one — *is* closed: a secured target refuses
  it at registration.
- **The existence of a route, on an automatic `OPTIONS`.** Express replies
  before any layer on the route runs, so no handler executes and nothing is
  authorized away — but the path and its method list are disclosed to an
  anonymous caller. A route registered with `app.all` or `.options` does not
  have this property, because Express dispatches to it and the declaration
  runs.
- **What a `passthrough()` actually does.** It is the author's word that a
  handler is middleware and **never serves a resource**. Terminating a CORS
  preflight is not serving a resource, so `cors()` is a passthrough; anything
  that can answer a request *for something* is a route and declares. That is
  why it takes a reason. The brand goes on the wrapper `passthrough()` returns,
  never on the function passed in, so nothing the caller still holds is
  vouched for.
- **What a `notFound()` actually does, beyond its status.** What it *cannot* do
  is protect something: the wrapper sets `404` before the handler runs, clamps
  any attempt to set a status below `400` while it runs, and forces `404` back
  if the status is under `400` when it returns — so a terminal that tried to
  answer `200` answers `404` instead. It is accepted in exactly one position,
  `app.use(notFound(handler))`: no path argument, no other handler in the call,
  never on `get`/`post`/`all`/`route()`, and last. `app.use("/admin",
  notFound(handler))` — a catch-all serving every method under a prefix with no
  declaration and no call to the center — is refused at startup. What is left
  unprotected is the handler's own content: it may still read the request and
  put anything it likes in a `404` body.
- **A second copy of this package in one process.** `secured()` would not
  recognise the other copy's declarations — a refusal to start, not a hole.
- **A repeat that never reached Node.** The line count is of what Node parsed.
  A proxy in front that already dropped the second `Authorization` line hands
  over one line, which is one credential; one that *folds* the two hands over
  `"Bearer a, Bearer b"`, which still reads as none.
- **Anything after the guard runs.** A knob fence, a tenant check, an ownership
  check are the handler's.
- **The method, if something upstream rewrote it.** `X-HTTP-Method-Override` is
  ignored here and always will be; mount any override middleware **before** the
  guard, or the requirement is decided about one method and the route runs as
  another.

## Migrating an Express app

Every construct the three services contain, in the spelling this package
accepts.

```ts
import type { ErrorRequestHandler } from "express";

const app = secured(express());

// 1. Health routes never read identity: the header is not read and the
//    center is not called, so they stay up while auth-service is down.
//    allowPublic() is for reads whose answer depends on an OPTIONAL identity.
app.get("/health", auth.ignoreCredentials(), health);
app.get("/api/fleet/health", auth.ignoreCredentials(), health);

// 2. A generated router (tsoa) has no call site for a declaration, so the
//    guard goes on the MOUNT, ahead of it. The resolver is a function of the
//    METHOD alone. See the note below: this is the one shape that is checked
//    at runtime rather than at startup.
const generatedRouter = express.Router();
RegisterRoutes(generatedRouter);
app.use(
  "/api/fleet/v1",
  auth.guard(({ method }) => (method === "GET" ? "session" : "fleet:control")),
  generatedRouter
);

// 3. A DECLARED MOUNT: the leading declaration covers everything after it, so
//    third-party middleware that cannot be branded needs no wrapper.
//    Swagger and static files never read identity either.
app.use("/api/fleet/swagger", auth.ignoreCredentials(), swaggerUi.serve, swaggerUi.setup(spec));
app.use("/assets", auth.ignoreCredentials(), express.static(assetDir));
app.use("/proxy", auth.requireSession(), express.raw({ type: "*/*", limit: "5mb" }), proxy);

// 4. Middleware that never answers says so, once, with a reason.
app.use(passthrough(express.json(), "parses bodies; never answers"));
app.use(passthrough(cors(corsOptions), "answers preflights; never serves a resource"));

// 5. The terminal JSON 404. It serves no resource, so it needs no credential
//    and never asks the center — and nothing but an error handler may follow it.
app.use(notFound((_req, res) => res.status(404).json({ error: { message: "not found" } })));

// 6. Error handlers (arity 4) are accepted as they are: Express invokes such a
//    layer only with an error already in hand, so it can never serve a route.
//    Annotate it — Express's own `use()` overloads infer the 3-argument shape,
//    so an inline 4-argument arrow is an implicit-any under `strict`.
const onError: ErrorRequestHandler = (_err, _req, res, _next) => {
  res.status(500).json({ error: { message: "internal" } });
};
app.use(onError);
```

**Always give an `ignoreCredentials()` or `allowPublic()` mount a path.**
`app.use("/assets", auth.ignoreCredentials(), express.static(assetDir))` covers
`/assets` only. Written without the path, the same mount matches every request,
and every mutating request that reaches it — including a `POST` meant for a
route registered further down — is answered `500` there, because a mount sees
every method and neither declaration lets a mutation through. It fails closed,
but it takes every write in the service down with it.

**A generated router is the one construct startup checking cannot see inside.**
`RegisterRoutes()` registers onto a plain `express.Router()`, which is not
`secured()` — it cannot be, because the routes it adds carry no declarations
and every one of them would be refused. The guard on the mount is what protects
them, and it protects them **at runtime**: every request Express routes into
that router passes the guard first, so an undeclared route inside it is still
answered only if the guard's resolver allowed the method. What is lost is the
boot-time failure — a route added inside the generated router that needs a
different requirement from its method's is not detected at startup, because
there is nothing to detect it at. CI registers exactly this shape against the
packed tarball and makes real requests through it (anonymous `GET` → `401`,
credentialed `GET` → `200`, a `POST` on a session without the scope → `403`,
an unmatched path → the app's own `404`), because a typecheck cannot see any
of that. Do not `secured()` the generated router, and do not put the guard
inside it and then mount it bare: an arity-3 router mounted with no declaration
ahead of it is refused, which is the boot failure that found this.

### A gap the migration cannot close: the shared-secret callers

automation-service's `knobWriteGuard` picks its requirement from the
`X-Service-Secret` header, and `POST /events` uses `requireServiceSecret()`;
this package has no shared-secret primitive and will not get one, because
[decision 21][d21] says a machine caller presents a Clerk M2M token like every
other caller and is fenced on what the center says about it. So this is a
**behaviour change the consumer has to plan**, not a spelling to translate: the
callers of those routes must be issued M2M tokens and start sending
`Authorization: Bearer …` before the routes are migrated, and the routes then
declare an ordinary scope and add `kindOf(res) === "machine"` inside the
handler where the secret check used to be. Until both halves have shipped,
leave those two routes on their existing guard and migrate the rest around
them — a route that swaps a shared secret for a scope before its callers hold
tokens is a `401` for every caller, not a tightening.

st-gateway is the one consumer that does **not** secure its app: `/proxy`
forwards anonymous mutations by design (`POST /register` carries the caller's
own account token, and auth-service polls `GET /` with no credential), and this
package has no spelling for "a mutating route that needs no credential" —
`allowPublic()` answers `500` there, and `ignoreCredentials()` refuses to
register on a mutating method and answers `500` if one reaches it through a
mount, deliberately. The gateway uses
`createLaneDeriver` only; the declared mount above is what it would write if it
ever authorized.

**Pass `timeoutMs: 250` to the gateway's lane deriver.** The default is 1000 ms
(the fixture's `clientTimeoutMs`), which is the right budget for a decision
that *rejects* — there, waiting is better than a wrong answer. The lane is not
that: it never rejects, and a center that does not answer in time yields
`background`, which is the same lane an anonymous caller gets. So the whole
cost of a slow center is paid on the latency of every credentialed proxied
request, in exchange for an answer the gateway is willing to guess anyway.
250 ms is comfortably above a healthy center's round trip on the same network
and low enough that a hanging one costs a quarter of a second rather than a
full one before the request proceeds.

### Reading the identity

`identityOf(res)`, `actorOf(res)`, `kindOf(res)`, `hasScope(res, scope)` and
`requirementOf(res)` are the **only** accessors. The values live in a
module-private `WeakMap` keyed on the response, so there is no `res.locals` key
to read instead — the identity, the requirement and the memo are all in the one
place, and none of them appears in `Object.keys(res.locals)`, in a
`JSON.stringify` of it, or in `util.inspect(res.locals, { showHidden: true })`,
which *does* print Symbol-keyed properties.
On a route declared `ignoreCredentials()`, `identityOf`, `actorOf` and
`kindOf` are `null` and `hasScope` is `false` whatever the caller sent, even
behind a `guard()` that verified someone; `requirementOf` is
`"ignore-credentials"` (exported as `CREDENTIALS_IGNORED`).
When a request passes more than one enforcement point — a `guard()` on the
mount and the route's own declaration, or nested declared mounts —
`requirementOf` reports the **innermost** one, the last to run: under
`guard("session")`, a route declaring `requireScope("fleet:control")` reports
`"fleet:control"`, and one declaring `ignoreCredentials()` reports
`"ignore-credentials"`. Every enforcement point on the way was still checked.
There is deliberately no second copy of `kind`: a knob fence is
`kindOf(res) === "machine"`, never a look at the `sub` prefix.

## Reference

### API

| Export | What it is |
|---|---|
| `createExpressAuth(config \| introspector \| authorizer)` | `requireScope(scope)`, `requireSession()`, `allowPublic()`, `ignoreCredentials()`, `guard(requirement \| resolver)` |
| `secured(routerOrAppOrRoute)` | Patches in place; enforces the registration rules. Idempotent |
| `passthrough(handler, why)` | Returns a branded wrapper around middleware that never serves a resource |
| `notFound(handler)` | Returns a branded wrapper that forces a 404; accepted only as `use(notFound(h))`, last |
| `identityOf` / `actorOf` / `kindOf` / `hasScope` / `requirementOf` | The accessors |
| `createAuthorizer(config \| introspector)` | The framework-agnostic policy: `authorize({ method, requires, authorization })` |
| `createLaneDeriver(config \| introspector)` | st-gateway's lane policy |
| `createIntrospector(config)`, `splitScopes`, `bearerFrom`, `isSafeMethod` | The pieces underneath |
| `authorizationLines(rawHeaders)` | How many `Authorization` lines a request carried; above one is no credential. For callers of `createAuthorizer` and `createLaneDeriver` |
| `loadIntrospectionConfig(env?)`, `IntrospectionConfigError` | Startup validation |
| `MESSAGES`, `CREDENTIALS_IGNORED`, `SECRET_HEADER`, `ENV_URL`, `ENV_SECRET`, `DEFAULT_TIMEOUT_MS`, `DEFAULT_MAX_RESPONSE_BYTES` | Constants |

`requireScope` throws at startup for `""`, whitespace, `"none"`, `"session"`
and `"ignore-credentials"`: the last three are the reserved words for the other
intents, and spelled as a scope each read as a demand while silently producing
its opposite. A fixed `guard("ignore-credentials")` throws too, and a resolver
returning it is undeclared: `ignoreCredentials()` is a declaration only.

### Behaviour

Rows are in evaluation order, and the first is first for a reason.

| Situation | Answer | Center called |
|---|---|---|
| Route declaring `ignoreCredentials()`, **safe** method, any header or none | proceeds, identity `null`, header **not read** | **no** |
| Route declaring `ignoreCredentials()`, **mutating** method (via a mount) | `500` `this route declares no required scope`, header **not read** | **no** |
| **Mutating** route declaring `"none"` | `500` `this route declares no required scope` | **no** |
| An **undeclared** route, on any method | `500` `this route declares no required scope` | **no** |
| No `Authorization`, **safe** method declaring `"none"` | proceeds as a visitor, identity `null` | **no** |
| `Authorization` that is not `Bearer <something>` | `401` `a bearer token is required` | **no** |
| **Two or more** `Authorization` lines, any values, any name case | read as **no** `Authorization`: the two rows either side of this one | **no** |
| No `Authorization`, route declaring a session or a scope | `401` `a bearer token is required` | **no** |
| `{"active": false}` | `401` `invalid or expired session`, on **every** method | yes |
| Active, route declares `"session"` | proceeds, even with no scopes at all — `"scope":""` and no `scope` key alike (RFC 7662 makes it optional) | yes |
| Active, route's scope missing | `403` `this action requires a scope this session does not carry` — the scope is **not** named | yes |
| Active, route's scope present | proceeds with `{sub, kind, scopes}` | yes |
| Center unreachable, timed out, non-2xx, malformed, or rejecting our secret | `503` `the authentication service could not process this request` | yes |

Every rejection uses the `{"error":{"message":…}}` envelope. Methods and the
bearer scheme are compared **case-insensitively**; scope literals **exactly** —
not by prefix, not by namespace walk, not case-folded — so `fleet:control:read`
and `FLEET:CONTROL` both fail a route requiring `fleet:control`. `scope` is
split on whitespace **runs** with empties discarded, matching
`strings.Fields`, `/\s+/` and `\s+` in the other implementations. `kind` is the
center's answer, used verbatim. `GET`, `HEAD` and `OPTIONS` are RFC 9110
§9.2.1's safe methods (`meta` fixture `version: 2`, owner's delegate
2026-09-21).

### Environment

| Variable | Meaning |
|---|---|
| `AUTH_INTROSPECTION_URL` | The **full** endpoint URL, `/auth/v1/introspect` included. POSTed to verbatim: never a base URL, never joined with a suffix |
| `AUTH_INTROSPECTION_SECRET` | The caller secret, sent as `X-Introspection-Secret`. Never the vault's `AUTH_SERVICE_SHARED_SECRET` |

Both are required. A blank value, a non-`http(s)` URL, a URL with a query
string, or a missing `globalThis.fetch` all refuse to start — the alternative
being a `503` on every credentialed request that reads as an auth outage — and
no message ever contains the secret.

### Lane policy — st-gateway's shape

A separate export, so nothing adopts it by accident. It never rejects, never
throws and never answers `503`: anything other than an active `operator` is
`background`, including a center that does not answer, because a gateway that
failed closed would take the public read surface down with auth-service.

```ts
const deriver = createLaneDeriver({ ...config, timeoutMs: 250 });
const header = authorizationLines(req.rawHeaders) > 1 ? null : req.header("Authorization");
const lane = await deriver.derive(header); // "interactive" | "background"
```

The line-count guard in front of `derive` is not optional: see the next section.

**It awaits the center**, so a *hanging* one adds up to `timeoutMs` to every
**credentialed** request the gateway proxies; anonymous requests are unaffected,
since nothing to introspect keeps the center off the hot path of the public map.
`timeoutMs` defaults to 1000 ms (the fixture's `clientTimeoutMs`), a proxy may
reasonably pass less — **250 ms is the recommendation for st-gateway**, for the
reason given in the migration section — and a test bounds the elapsed time
against a stub that never answers.

### Two `Authorization` lines — outside the adapter

`createAuthorizer().authorize({ authorization })` and `createLaneDeriver().derive()`
take one header **value**, and a value cannot show that the request carried
two lines: Node has already kept the first and thrown the second away. Handed
`req.header("Authorization")` for `Bearer a` + `Bearer b`, they read
`"Bearer a"` — a well-formed credential the caller picked by putting it first.
The Express adapter counts the lines itself (P7); anything calling these two
directly counts them first and passes `null` for more than one:

```ts
import {
  authorizationLines,
  bearerFrom,
  createLaneDeriver,
} from "@v-m-pioneer-trading/introspection-client";

// What Node hands a handler for `Authorization: Bearer a` + `authorization: Bearer b`.
const rawHeaders = ["Host", "localhost", "Authorization", "Bearer a", "authorization", "Bearer b"];
const parsed = "Bearer a"; // req.header("Authorization"): the second line is gone

if (bearerFrom(parsed) !== "a") throw new Error("the parsed value alone is one credential");
if (authorizationLines(rawHeaders) !== 2) throw new Error("the raw lines are two");

// So the rule goes in front of the call, on the real request:
const header = authorizationLines(req.rawHeaders) > 1 ? null : req.header("Authorization");
const lane = await createLaneDeriver(config).derive(header); // null is "background", no center call
```

`authorizationLines` compares names case-insensitively, counts names only (a
header whose *value* reads `authorization` is not a line), and counts an empty
`Authorization:` line like any other: `Bearer b` behind an empty first line
is two lines, not a credential. `null` then means what it means everywhere —
`401 a bearer token is required` where a session is needed, a visitor or the
`background` lane where it is not, and no call to the center.

### Security notes

- **The token is never parsed, decoded, logged or inspected**, and nothing in
  this package logs at all. It is URL-encoded into a form body — never a URL,
  where an access log would keep it. Errors are swallowed at the boundary
  rather than wrapped, because a wrapped fetch error carries the URL.
- **Redirects are not followed** (`redirect: "manual"`), so a `Location` header
  cannot carry `X-Introspection-Secret` to another host.
- **One call, a 1 s timeout, zero retries, no cache.** A retry against a center
  that is down doubles the latency of every failing request and changes nothing.
- **`503` never leaks upstream detail**, including the center's own `401` about
  *our* caller secret — relaying that would tell an operator to sign in again,
  forever, against a service that cannot accept them. A partial or wrongly
  typed answer is `503` rather than `active: false`, so a half-deployed center
  does not become a fleet-wide `401` storm, and the body is read under a 64 KiB
  cap.
- **A malformed `Authorization` header is never repaired.** `"Bearer"`,
  `"Bearer "`, `"Bearer abc def"` and a value carrying two credentials
  (`"Bearer a, Bearer b"`, as a proxy that folds a repeated header produces)
  all read as *no credential*. Two `Authorization` **request headers** do not
  produce that value: `Authorization` is single-valued to Node's parser, which
  discards the repeat, so `req.header("Authorization")` is the **first** line.
  Up to 1.1.1 the adapter verified that first line, letting a caller choose
  which of two credentials was checked; it now counts `rawHeaders` and reads
  two lines as no credential (P7). Both the parser's behaviour and the
  adapter's answer are pinned by raw-socket tests against real Express.
- **A guard that cannot do its job fails closed.** An injected introspector that
  rejects or throws calls `next(error)` — never bare `next()`, which would run
  the handler the guard just failed to authorize.

## Development

```sh
npm ci && npm run typecheck && npm run build && npm test && npm run check:readme
```

`check:readme` extracts **every** fenced `ts`/`js` snippet on this page,
compiles it against `src/` and then **runs** it. Running is the half that
matters: `secured()` enforces at registration time, so a snippet that boots is
a snippet a consumer can copy — and the fourth review found this file
instructing fleet-service to write a construct that throws at startup. Two
transforms and no others: the package's own name becomes a relative import of
`src/`, and a snippet's leading `import` lines are hoisted out of the wrapper
its body goes into. Free identifiers (`auth`, `RegisterRoutes`, `swaggerUi`, …)
come from `scripts/readme-prelude.ts`, where `RegisterRoutes` really registers
routes and `swaggerUi.serve` really is an array — a stub that was merely typed
would prove nothing about what `secured()` does with it.

CI additionally packs the tarball, installs it into a scratch project and
typechecks two probes with `skipLibCheck: false` — one without
`@types/express` (the core claim), one with a real Express app (the adapter
claim) — then proves three things against the **packed** tarball at runtime,
because a typecheck cannot see them: the registration rules (including that
a `notFound()` is refused on a path or alongside another handler), the
generated-router mount answering live requests as the migration section
promises, and two `Authorization` lines written to a raw socket reading as no
credential with no call to the center.

**Re-vendoring the fixture.** `meta` owns it and this repository holds a copy so
drift shows in a diff, so change `meta` first; the exact commands and the
current provenance live in [`test/fixtures/SOURCE`](test/fixtures/SOURCE).
`meta` runs [`scripts/validate-fixtures.mjs`][validate] on every PR, and the
suite here recomputes the hash, asserts the sorted case names and **fails on an
unknown assertion key**, so a case added upstream is a red test rather than one
quietly skipped.

**Releasing.** Green on `main`, bump `version`, merge, push a matching tag
(`git tag v1.0.0 && git push origin v1.0.0`). The release workflow refuses a
tag that disagrees with `package.json`, then builds, tests, packs and attaches
the `.tgz` to a GitHub Release; `contents: write` lives on that one job.

## Licence

MIT — see [LICENSE](LICENSE). Chosen here because this package is installed
from a public URL by builds outside its own repository.

[d21]: https://github.com/V-M-Pioneer-Trading/meta/blob/main/docs/design/auth-design.md#21-one-verifier-every-service-asks-auth-service-what-a-token-carries
[fixture]: https://github.com/V-M-Pioneer-Trading/meta/blob/main/fixtures/introspection.json
[validate]: https://github.com/V-M-Pioneer-Trading/meta/blob/main/scripts/validate-fixtures.mjs
