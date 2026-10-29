# Repo map: V-M-Pioneer-Trading/clerk-client
Verified against 31d2cbc 2026-10-29.

## Purpose
- TS client for auth-service introspection: default-deny guards, Express 4 adapter, st-gateway lane policy. Version 2.0.1. `package.json:2-4`, `src/index.ts:3-15`
- Local folder is `ts-introspection-client`; GitHub repo and package name are `clerk-client`. `package.json:2`
- No registry: consumers install the GitHub Release tarball by URL. `README.md:25`

## Layout (`src/`)
- `src/index.ts`: public surface, re-exports everything below. `src/index.ts:17-76`
- `src/core.ts`: `createAuthorizer`, `bearerFrom`, `isSafeMethod`, `authorizationLines`, `soleAuthorizationLine`. `src/core.ts:328`, `:99`, `:42`, `:258`, `:278`
- `src/center.ts`: `createIntrospector`, `splitScopes`; the HTTP call to auth-service. `src/center.ts:161`, `:49`
- `src/strictJson.ts`: strict JSON parse rejecting duplicate keys. `src/strictJson.ts:222`
- `src/express.ts`: `createExpressAuth` (`requireScope`, `requireSession`, `allowPublic`, `ignoreCredentials`, `guard`), `secured`, `passthrough`, `notFound`, `identityOf`/`actorOf`/`kindOf`/`hasScope`. `src/express.ts:964`, `:776`, `:344`, `:409`, `:211-245`
- `src/gateway.ts`: `createLaneDeriver().derive(header)`: "interactive" only for an active operator, else "background", never throws. `src/gateway.ts:36-60`
- `src/config.ts`: `loadIntrospectionConfig`, `IntrospectionConfigError`. `src/config.ts:41`, `:17`
- `src/m2mToken.ts`: `createCentralM2MTokenSource`, `M2MTokenError` (unknown-caller | unavailable | malformed). `src/m2mToken.ts:151`, `:41`, `:39`
- `src/messages.ts`: `MESSAGES`, `SECRET_HEADER`, `ENV_URL`, `ENV_SECRET`, `DEFAULT_TIMEOUT_MS` (1000), `DEFAULT_MAX_RESPONSE_BYTES` (64 KiB). `src/messages.ts:13-44`
- `src/types.ts`: shared types. `src/types.ts`
- `test/`: jest suites plus `test/fixtures/` and `test/support/`. `jest.config.js:3-6`
- `scripts/check-readme.mjs`, `scripts/readme-prelude.ts`: compile and run README snippets. `scripts/check-readme.mjs:1-27`

## Security-sensitive logic
- Rule order: non-safe method with `none` -> 500 before the header read, no center call. `src/core.ts:340-346`
- No token: `none` -> visitor, no center call; otherwise 401. `src/core.ts:348-357`
- Inactive token -> 401 on any method, never visitor. `src/core.ts:301-305`
- Scope is exact membership, else 403. `src/core.ts:313-320`
- `bearerFrom`: array joined ", "; trim, split on whitespace, exactly 2 parts, scheme case-insensitive. `src/core.ts:103-107`
- Authorization lines counted from `rawHeaders` even indices; more than one line or an unknowable count = no credential. Express reads the credential only this way. `src/core.ts:193-216`, `src/core.ts:173-187`, `src/core.ts:278-281`, `src/express.ts:1159`
- Center call: POST, token in form body, `redirect: "manual"`, no cache, no retry, timeout covers the body. `src/center.ts:166-195`
- Non-2xx -> unavailable before the body is read; response byte cap. `src/center.ts:197-203`, `src/center.ts:117-135`
- `readBody`: case-variant duplicate or mis-cased contract keys are malformed; `active` strictly boolean; `sub` non-empty; `exp` finite; `kind` operator|machine. `src/center.ts:72-108`
- `splitScopes` splits on `[ \t\r\n]+` only. `src/center.ts:38-50`
- `unavailable` carries no detail; errors are swallowed (they may carry the URL); nothing logs. `src/center.ts:25-29`, `src/center.ts:228-232`
- `ignoreCredentials` only on get/head/options/use(), else startup throw. `src/express.ts:601-632`
- `secured()` refuses undeclared routes at registration. `src/express.ts:776-835`
- `loadIntrospectionConfig`: both env vars required and non-blank, http/https, global fetch present, no query string. `src/config.ts:24-81`
- M2M: secret non-empty without CR/LF; JWT payload read unverified for `iat`/`exp` only; lifetime <= 7 days; refresh at half-life; only 200 accepted, 401 -> unknown-caller; one retry on timeout only; failure spacing 10 s; unexpired cached token served on failure except unknown-caller. `src/m2mToken.ts:138`, `:112-131`, `:31`, `:188-203`, `:224-227`, `:28`, `:235`, `:241-246`

## Calls / called-by
- Calls auth-service: `POST AUTH_INTROSPECTION_URL` verbatim with header `X-Introspection-Secret`. `src/center.ts:176-181`, `src/messages.ts:32-38`, `README.md:503`
- Calls auth-service M2M endpoint with `X-M2M-Caller-Secret`. `src/m2mToken.ts:22`, `src/m2mToken.ts:175-177`, `README.md:418`
- Called by (pin v2.0.1 release URL): `../agent-service/package.json:24`, `../automation-service/package.json:19`, `../fleet-service/package.json:20`, `../st-gateway/package.json:18`; lockfile pins sha512, e.g. `../fleet-service/package-lock.json:2602-2605`
- Entry points in consumers: `../agent-service/src/server.ts:211`, `../fleet-service/src/server.ts:151` (`createExpressAuth`), `../st-gateway/src/server.ts:189` (`createLaneDeriver`), `../automation-service/src/config.ts:90` (M2M)
- auth-service is not a consumer; it is the verifier. `../auth-service/CLAUDE.md:77-78`
- Stale: ai-service pins the old `@v-m-pioneer-trading/introspection-client` v1.2.0 from the pre-rename repo URL and uses `createCentralM2MTokenSource`. `../ai-service/package.json:17`, `../ai-service/src/server.ts:2`, `../ai-service/src/server.ts:95`. Old URL still resolving after the rename: (unverified)
- Design docs live in meta: `../meta/docs/design/auth-design.md`, `../meta/docs/design/token-introspection.md`. `src/center.ts:10`, `src/center.ts:159`, `src/center.ts:192`

## Vendored fixture
- `test/fixtures/introspection.json` from meta `../meta/fixtures/introspection.json`; `test/fixtures/SOURCE` pins commit f226e5f, blob f41e25d, version 7, 75 cases, 77984 bytes, sha256. `test/fixtures/SOURCE:3-10`
- Both files are `-text` (no EOL rewrite). `test/fixtures/SOURCE`, `.gitattributes:6-7`
- Conformance checks bytes and sha against SOURCE and against a hardcoded sha literal; asserts version 7 and the sorted case names. `test/conformance.test.ts:61-72`, `:162`, `:76`, `:138`
- An unknown `expect` key throws. `test/support/fixture.ts:101-106`
- Re-vendor: commands at `test/fixtures/SOURCE:33-39`; also update the sha literal and the version test (`test/conformance.test.ts:61-72`, `:162`), which SOURCE does not mention. Change meta first.
- meta validates the fixture. `../meta/.github/workflows/validate.yml:45-46`
- Merge vs squash of the meta PR changes only the SOURCE commit. `test/fixtures/SOURCE:12-16`

## Build / test
- Scripts: build (`tsc -p tsconfig.build.json`), typecheck, test (jest), lint (`--max-warnings 0`), check:readme, prepack = build. `package.json:22-29`
- Local one-liner. `README.md:621-625`
- Lint `base` comes from the eslint-config v1.1.0 tarball. `eslint.config.mjs:1-7`, `package.json:35`
- Jest: ts-jest, `detectOpenHandles`. `jest.config.js:3-11`
- CommonJS, node resolution, no `exports` map; node >= 18. `tsconfig.json:5-8`, `package.json:19-21`
- Express types are local so the `.d.ts` needs no `@types/express`. `src/express.ts:88-139`, `.github/workflows/ci.yml:76-87`
- Express 4 dev deps. `package.json:31`, `package.json:37`

## CI (`.github/workflows/ci.yml`, job `test`)
- Runs on pull_request and push to main; Node 22; read-only token. `.github/workflows/ci.yml:3-9`, `.github/workflows/ci.yml:14-15`, `.github/workflows/ci.yml:30`
- Actions are SHA-pinned with a version comment. `.github/workflows/ci.yml:21-28`, `.github/workflows/release.yml:24-30`
- Steps: `npm ci` `.github/workflows/ci.yml:33`, lint `:37`, typecheck `:41`, build `:43`, test `:45`, check:readme `:53`.
- Tarball steps in `/tmp/consumer`: "Pack and check the tarball's contents" :57, "Install the tarball into a scratch CommonJS project" :88, "Typecheck the adapter against a real Express consumer" :154, "Prove the tarball enforces the registration rules at startup" :262, "Prove the generated-router mount enforces at runtime, from the tarball" :315, "Prove two Authorization lines are no credential, from the tarball" :419, "Prove a duplicated key is a malformed answer, from the tarball" :576.
- The `require()` export check is a hardcoded 8-name list; a new export is unchecked unless added. `.github/workflows/ci.yml:94-98`

## Release (`.github/workflows/release.yml`)
- Trigger: tag push `v*`; job `release` holds `contents: write`. `.github/workflows/release.yml:8-10`, `.github/workflows/release.yml:21-22`
- Steps: tag == `package.json` version, `npm ci`, typecheck, build, test, pack, then `gh release create ... --generate-notes`. `.github/workflows/release.yml:35-74`
- No lint, check:readme or tarball probes in release. `.github/workflows/release.yml:44-59`
- Process: green main, bump version, merge, push a matching tag. `README.md:658-661`
- Consumer bump is a manual URL + lockfile edit in each consumer. Pin lines: `../agent-service/package.json:24`, `../fleet-service/package.json:20`, `../automation-service/package.json:19`, `../st-gateway/package.json:18` (lockfile half: unverified)

## Traps
- Green `npm test` is not green CI: the tarball-only steps run only in CI. `.github/workflows/ci.yml:57-667`
- ts-jest typechecks only imported files; `npm run typecheck` and build cover the rest. `.github/workflows/ci.yml:39-41`
- README snippets are compiled and run via `scripts/readme-prelude.ts`; `.readme-check/` is gitignored and lint-ignored. `scripts/check-readme.mjs:1-27`, `.gitignore:4`, `eslint.config.mjs:7`
- BOM or invalid UTF-8 is read leniently here, unlike the Go and Java clients. `src/center.ts:205-210`
- CHANGELOG "Unreleased" is tests only: no code change, no release. `CHANGELOG.md:3-5`
