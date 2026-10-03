# Changelog

## 2.0.1 — 2026-10-03

Bug fix, no API change. Conforms to `meta` fixture version 6. Part of
V-M-Pioneer-Trading/meta#103 (the divergences were found porting
agent-service to TypeScript).

### Fixed

- **`scope` was split on every Unicode space (present in 1.0.0 through
  2.0.0).** `splitScopes` used `/\s+/`, which JavaScript defines to include
  VT, FF, U+00A0, U+2000–U+200A, U+3000, U+FEFF and more, so a token whose
  `scope` was `fleet:control` + U+00A0 + `agent:reset` satisfied a route
  requiring `fleet:control`, where the Go and Java clients answer `403`.
  Scopes are now separated by runs of space, tab, CR and LF only, empties
  discarded; every other character is part of the scope token.
- **Top-level keys that differ only in case were read as different keys
  (present in 1.0.0 through 2.0.0).** `{"active":true,…,"Active":false}`
  proceeded and `{"active":true,…,"Scope":"…"}` read as an absent scope,
  where the Go and Java clients answer `503`. Two top-level keys equal under
  `toLowerCase()`, or a contract key (`active`, `sub`, `scope`, `exp`,
  `kind`) spelled any other way, are now a malformed answer: `503`
  `the authentication service could not process this request` on a calling
  service and the `background` lane at the gateway, after one call. Below the
  top level only an exact repeat is refused, as before.

### Changed

- Fixture version 6 vendored (51 + 14 cases); the CI tarball proof also checks
  a case-variant key, a miscased contract key, a scope joined by U+00A0 and
  one joined by a tab.

## 2.0.0 — 2026-10-01

Rename only, no API change. The package is now
`@v-m-pioneer-trading/clerk-client` (formerly
`@v-m-pioneer-trading/introspection-client`, 1.x) and the repository is
V-M-Pioneer-Trading/clerk-client. Consumers change the dependency URL and the
import path; every export is identical to 1.2.0. The release tarball is
`v-m-pioneer-trading-clerk-client-2.0.0.tgz`.

## 1.2.0 — 2026-09-30

New export, no change to anything existing. Part of
V-M-Pioneer-Trading/meta#80 (auth-design decision 22).

### Added

- **`createCentralM2MTokenSource({ url, secret, fetch?, now?, timeoutMs? })`,
  `M2MTokenSource` and `M2MTokenError`**: the caller side of auth-service's
  machine-token endpoint, a port of automation-service's
  `createClerkM2MTokenSource` with the Clerk call replaced by one `POST` to
  the center (`X-M2M-Caller-Secret`, empty body, 1 s timeout). The token is
  cached in memory and refreshed at `iat + (exp - iat) / 2`, read from the
  unverified JWT, with a single refresh in flight. A failed refresh serves the
  cached token until it expires and is not repeated for 10 s. One immediate
  retry, after a timeout only (headers or body); never after a `503` or a
  `401`. A `401` always throws, even with a valid cached token. Every failure
  is an `M2MTokenError` with `kind` `"unknown-caller"`, `"unavailable"` or
  `"malformed"`, so a caller can exit on the first and continue on the others;
  `cause` on a transport failure carries only `code` and `name`. Options are
  validated at construction. A token whose lifetime is not finite, not
  positive, over 7 days, or already over is `malformed`. Neither the secret
  nor the token appears in an error or a log.

## 1.1.3 — 2026-09-30

Bug fix, no API change. Conforms to `meta` fixture version 5. Part of
V-M-Pioneer-Trading/meta#80.

### Fixed

- **A center answer naming the same key twice was read with the last value
  winning (present in 1.0.0 through 1.1.2).** The body was parsed with
  `JSON.parse`, so `{"active":true,"sub":"user_a","sub":"user_b",…}`
  proceeded as `user_b`, where the Go and Java clients answer `503`. A
  repeated key in any object, at any depth, compared after escapes are decoded
  (`"sub"` and `"s\u0075b"` are one key), is now a malformed answer: `503`
  `the authentication service could not process this request` on a calling
  service and the `background` lane at the gateway, after one call to the
  center. The same key in two different objects is still read. The body is
  parsed by a small strict reader (`src/strictJson.ts`) that otherwise
  accepts and builds exactly what `JSON.parse` does, still after the 64 KiB
  cap; it refuses nesting deeper than 1000 levels, as Jackson does by default.
  Not a bypass (the center is trusted and marshals a struct), but the three
  clients now agree on the fixture's rule (#6). Any depth is the Java
  client's rule (Jackson `STRICT_DUPLICATE_DETECTION`); the Go client checks
  the top-level members only.

### Changed

- Fixture version 5 vendored (meta `aa877e7`, 41 + 13 cases); its two
  duplicate-key cases also run through real Express with `createExpressAuth`
  and through `createLaneDeriver`.

## 1.1.2 — 2026-09-26

Security fix, plus one additive export. Conforms to `meta` fixture version 4.
Part of V-M-Pioneer-Trading/meta#80.

### Security

- **Two `Authorization` lines let the caller pick which credential was
  verified (present in 1.0.0 through 1.1.1).** Node's HTTP parser keeps the
  first `Authorization` line and discards any repeat, and the adapter read
  `req.header("Authorization")`, so `Bearer a` + `Bearer b` asked the center
  about `a`, and an empty line + `Bearer b` was served as a visitor. The
  adapter now counts `Authorization` lines in `req.rawHeaders`
  (case-insensitively) and reads more than one, whatever they hold, as no
  credential: `401 a bearer token is required` on session and scope routes, a
  visitor on `allowPublic()` reads, and no call to the center. The rule applies
  to `requireScope`, `requireSession`, `allowPublic` and `guard` alike;
  `ignoreCredentials()` still reads no header. Upgrade any service on 1.1.1 or
  earlier.
- **A count that cannot be known is no credential either.** Past
  `2 × server.maxHeadersCount` header entries (2000 by default, about five
  kilobytes of filler) Node 22 answers `431` before any handler runs, but
  Node 25 hands the app a truncated `rawHeaders`, so there a second
  `Authorization` line sent after ~1000 filler lines was never counted and the
  first was verified. A request whose `rawHeaders` has reached the limit in
  force is now no credential, even with one line. The limit is the stricter of
  `req.socket.server.maxHeadersCount` (Node's arithmetic; `0` means no limit)
  and `req.socket.parser.maxHeaderPairs`, because Node copies the server's
  setting into each connection's parser once, when it opens: raising or lifting
  `maxHeadersCount` on a live keep-alive connection would otherwise have read
  as "no limit" while the parser still truncated. Set it before the first
  connection. A request with no `rawHeaders` is no credential too.
- **The value verified is the one raw line, not `req.header()`.** With
  exactly one `Authorization` line, the adapter takes the credential from
  `rawHeaders` itself, so a middleware that set or rewrote
  `req.headers.authorization` is ignored: zero raw lines is no credential, and
  one raw line is verified as sent.

### Added

- `soleAuthorizationLine(req: RawHeaderSource): string | null`: the value of
  the request's one raw `Authorization` line, or `null` for none, several, or
  a count that cannot be known. `createAuthorizer().authorize()` and
  `createLaneDeriver().derive()` take one header value and cannot see a
  repeat, so their callers — st-gateway above all — pass
  `soleAuthorizationLine(req)` instead of `req.header("Authorization")`.
- `authorizationLines(req: RawHeaderSource): number`: the count alone, or
  `Infinity` when it cannot be known; `0` for an empty list.
- The `RawHeaderSource` type, `{ rawHeaders, socket? }`, which a Node or
  Express request satisfies. Both helpers take the request, not its
  `rawHeaders`, because the header limit lives on the connection.

### Changed

- **`RequestLike` gained a required `rawHeaders`.** A real Express `Request`
  already has it, so code that hands the adapter real requests is unaffected; a
  hand-written request double no longer typechecks until it adds one. At
  runtime a request without a `rawHeaders` array is read as carrying no
  credential, never as carrying one line. It also gained an optional
  `socket`, read only for `parser.maxHeaderPairs` and
  `server.maxHeadersCount`. `header()` is no longer read for the credential.
- Fixture version 4 vendored (meta `46c033e`, 40 + 12 cases); its four
  two-line cases run as real separate header lines through real Express and
  the lane recipe.

## 1.1.1 — 2026-09-23

Bug fix, no API change. Part of V-M-Pioneer-Trading/meta#80 (step 6).

### Fixed

- **An active answer with no `scope` key was read as malformed and answered
  `503` (present in 1.0.0 and 1.1.0).** RFC 7662 makes `scope` optional, and
  auth-service left it out for a verified token carrying no scopes, so a
  signed-in operator with no scopes could not reach a `"session"` route at
  all. An absent `scope` now means an empty scope list, exactly like
  `"scope":""`: a `"session"` route proceeds with `scopes: []`, and a route
  requiring a scope answers `403`. A `scope` that is present but not a string
  is still `503`. auth-service PR #4 also stops omitting the key; either side
  alone closes the hole.

## 1.1.0 — 2026-09-23

Additive, plus one security fix. Part of V-M-Pioneer-Trading/meta#80 (step 5).

### Security

- **`secured(app).del(...)` registered an undeclared route (present in 1.0.0).**
  Express 4's deprecated `app.del` is a wrapper around the `delete` Express
  captured when it loaded, so it bypassed the patched `delete` entirely:
  `secured(app).del("/d", handler)` registered with no declaration and served
  the `DELETE` to anyone. A secured app, router or route now refuses `del()` at
  registration, naming `delete(...)` as the spelling to use. No other Express 4
  route method or alias still points at Express's own function after
  `secured()`; a test pins that. Upgrade any service on 1.0.0.

### Added

- `auth.ignoreCredentials()`: a declaration for routes that never read
  identity (health, API docs, static files). The `Authorization` header is
  not read and the center is never called; `identityOf(res)` is `null` and
  `requirementOf(res)` is `"ignore-credentials"`. Accepted on `get`, `head`,
  `options` and `use()` mounts only; refused at registration on any other
  method, and a mutating request reaching it through a mount is `500`.
- `CREDENTIALS_IGNORED` constant and `DeclaredRequirement` type exported.
- `"ignore-credentials"` is reserved: `requireScope()` and a fixed `guard()`
  refuse it, and a `guard()` resolver returning it is undeclared (`500`).
- `allowPublic()`, `authorize()` and the fixture are unchanged.
- **`ExpressAuth` gained a member** (`ignoreCredentials`). Code that only
  calls `createExpressAuth()` is unaffected; a hand-written object typed as
  `ExpressAuth` (a test double, a wrapper) no longer typechecks until it adds
  one.

## 1.0.0 — 2026-09-23

- First release: default-deny `createAuthorizer`, the Express 4 adapter
  (`secured`, `requireScope`, `requireSession`, `allowPublic`, `guard`,
  `passthrough`, `notFound`, accessors), st-gateway's `createLaneDeriver`,
  conformance with `meta/fixtures/introspection.json`.
