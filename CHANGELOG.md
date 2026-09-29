# Changelog

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

### Added

- `authorizationLines(rawHeaders)`: how many `Authorization` lines a request
  carried. `createAuthorizer().authorize()` and `createLaneDeriver().derive()`
  take one header value and cannot see a repeat, so their callers — st-gateway
  above all — pass `null` when this is above one. The README shows the recipe.

### Changed

- **`RequestLike` gained a required `rawHeaders`.** A real Express `Request`
  already has it, so code that hands the adapter real requests is unaffected; a
  hand-written request double no longer typechecks until it adds one. At
  runtime a request without a `rawHeaders` array is read as carrying no
  credential, never as carrying one line.
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
