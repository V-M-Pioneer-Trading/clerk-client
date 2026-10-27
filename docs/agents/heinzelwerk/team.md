# Team rules

How heinzelwerk agents work in this repo. Mode rules (single repo vs workspace) live in the `heinzelwerk:team-modes` skill. This file holds only what is specific to this repo.

- **Role**: shared package (`@v-m-pioneer-trading/clerk-client`; GitHub repo `V-M-Pioneer-Trading/clerk-client`, local folder `ts-introspection-client`). Introspection client, default-deny route guards, Express adapter, lane policy, M2M token source. Zero runtime deps; released as a GitHub release tarball
- **Backend paths**: `src/`, `test/`, `scripts/`
- **Shared paths** (only the owner named in the task edits them): `test/fixtures/introspection.json` (vendored from meta)
- **Worktree setup**: `npm ci --no-audit --no-fund`
- **Checks** (validator runs every one, in order):
  1. `npm audit --audit-level=high`
  2. `npm run lint --silent`
  3. `npm run typecheck --silent`
  4. `npm run build --silent`
  5. `npm test --silent -- --silent`
  6. `npm run check:readme --silent`
- **Security**: no secret scan runs yet: gitleaks is not installed and no pre-commit hook exists (planned: `gitleaks git --pre-commit --staged` in `.git/hooks/pre-commit`), so check every diff for secrets by eye · dependency audit in checks
- **Coding standards**: `README.md` (declaration rules, default-deny); lint rules come from `@v-m-pioneer-trading/eslint-config`
- **Risk areas** (validator reviews diffs touching these on Opus). The whole package is one: it decides access in four services
  - default-deny guard and declaration order: a route without a declaration is never served
  - Authorization handling: two Authorization lines are never a credential; the token is never logged or parsed
  - M2M source: 401 and 503 are never retried
  - `.github/workflows/`: the tarball-based proofs in `ci.yml` and the release
- **Contracts**:
  - the package API: provider this repo; consumers agent-service, automation-service, fleet-service, st-gateway (2.0.1). ai-service still pins the predecessor `introspection-client` 1.2.0 from the old repo name. A change is a release (`v*` tag matching `package.json`) plus one bump PR per consumer
  - behaviour pinned by `meta/fixtures/introspection.json` (provider meta); change meta first, then re-vendor
