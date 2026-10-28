# Team rules

How heinzelwerk agents work in this repo (GitHub V-M-Pioneer-Trading/clerk-client, package `@v-m-pioneer-trading/clerk-client`; local folder `ts-introspection-client`). Mode rules (single repo vs workspace) live in the `heinzelwerk:team-modes` skill. This file holds only what is specific to this repo.

- **Autonomy**: full. Agents merge and apply on their own; breakages are learnings. Secrets are never published (name the variable, never the value), and the gate never merges its own policy.
- **Shared paths** (a shared package: one task owns a change, consumers bump after the release): whole repo (`src/`, `test/`, `scripts/`)
- **Worktree setup**: `npm ci`
- **Checks** (copied from `.github/workflows/ci.yml`, job `test`, in order):
  - `npm run lint`
  - `npm run typecheck`
  - `npm run build`
  - `npm test`
  - `npm run check:readme` (compiles and runs every README snippet)
  - the seven tarball probes, ci.yml steps "Pack and check the tarball's contents" through "Prove a duplicated key is a malformed answer, from the tarball": run each step's script as written, in order (they share /tmp/consumer and the packed `.tgz`)
- **Checks verified on main**: 31d2cbc 2026-10-28
- **Coding standards**: `@v-m-pioneer-trading/eslint-config` base (`package.json:35`); rules in `README.md`
- **Risk areas** (validator reviews diffs touching these on Opus):
  - `src/**`: every export is authorization code for four services: default deny (`secured()` refuses undeclared routes), introspection answers, lane derivation, M2M token source
  - `test/fixtures/**`: conformance against meta's fixture; a new case there fails here until implemented
  - `README.md`: snippets run in CI
  - `.github/workflows/release.yml`: a `v*` tag must equal `package.json` version; push the tag only, the workflow creates the release
- **Contracts** (see team-modes **Contract changes**):
  - Provided: package exports (`src/index.ts`) · provider clerk-client; consumers pin the release tarball URL: agent-service, automation-service, fleet-service, st-gateway (ai-service still on the old `introspection-client` 1.2.0, V-M-Pioneer-Trading/meta#126)
  - Consumed: auth-service `POST /auth/v1/introspect` and `POST /auth/v1/m2m-token` · provider auth-service
  - Vendored: `test/fixtures/introspection.json`, copy of `../meta/fixtures/introspection.json`, pinned in `test/fixtures/SOURCE` · provider meta; a provider change means a re-vendor here
