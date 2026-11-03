# Route matching stays Express's job

A `guard()` resolver gets only `{ method }`, never a path, so the package has no second matcher: a `use`-mounted middleware runs before any route layer matches, and any path it reconstructed would be a second, worse matcher. The cost is no boot-time per-route checking inside generated routers, `src/express.ts:943`, `src/express.ts:1018`.

## Considered Options

1. The package matches paths itself: a `guard()` resolver is handed the path. Lost because inside a `use` mount no route has matched yet, so any path it reconstructed would be a second, worse matcher, and a prefix-mounted router, a trailing slash, a case-variant path or a `:parameter` would become a string the package looks up.
2. **Express matches; declarations live at registration and a resolver gets only `{ method }` (chosen).**

Source: README.md#Security model
