# Route matching stays Express's job

A `guard()` resolver gets only `{ method }`, never a path, so the package has no second matcher: a `use`-mounted middleware runs before any route layer matches, and any path it reconstructed would be a second, worse matcher. The cost is no boot-time per-route checking inside generated routers, `src/express.ts:935-941`.

Source: README.md#Migrating an Express app
