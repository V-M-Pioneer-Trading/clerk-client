# Team rules

How heinzelwerk agents work in this repo. Mode rules (single repo vs workspace) live in the `heinzelwerk:team-modes` skill. This file holds only what is specific to this repo; the workspace is described in V-M-Pioneer-Trading/meta `docs/agents/heinzelwerk/workspace.md`.

- **Autonomy**: full. Agents merge and apply on their own; breakages are learnings. Secrets are never published (name the variable, never the value), and the gate never merges its own policy.
- **Role**: shared package
- **Shared paths**: whole repo (provider: this repo; consumers install a release tarball)
- **Worktree setup**: `npm ci`
- **Checks** (validator runs every one, in order; copied from CI, quiet flags only):
  - `npm run lint`
  - `npm run typecheck`
  - `npm run build`
  - `npm test`
  - `npm run check:readme`
  - ci.yml steps "Pack and check the tarball's contents" through "Prove two Authorization lines are no credential, from the tarball" (ci.yml:57-575), verbatim and in order
  - ci.yml step "Prove a duplicated key is a malformed answer, from the tarball" (ci.yml:576-667), verbatim (unverified locally: fails on Windows at the tab-joined scope; green in CI on 31d2cbc)
  - `npm audit --audit-level=high` (red on main: V-M-Pioneer-Trading/meta#119)
- **Checks verified on main**: 31d2cbc 2026-10-27
- **Coding standards**: `README.md` (security model, declaration rules) and the shared `@v-m-pioneer-trading/eslint-config`
- **Risk areas** (validator reviews diffs touching these on Opus):
  - `src/**`: the default-deny guard every Node service uses; the lane deriver fails open by design
  - exports, package name, release tarball contents: a change is a release plus a bump in every consumer
  - `.github/workflows/**`: a merge to `main` deploys or releases
- **Contracts** (see team-modes **Contract changes**; validator checks every diff touching these):
  - Package API (`src/index.ts` exports) · provider clerk-client
  - Conformance fixture `test/fixtures/introspection.json`: vendored from meta `fixtures/introspection.json` · provider meta
