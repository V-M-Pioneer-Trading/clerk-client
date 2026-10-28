# Repo map

Verified against origin/main 31d2cbc on 2026-10-28. Facts only, each with its evidence (`path:line`). Sections: 1 purpose, 2 entry points, 3 unauthenticated, 4 money, 5 calls in/out, 6 build/run, 7 CI, 8 persistence, 9 patterns, 10 traps, 11 docs.

1. Purpose: zero-dep TS client for auth-service token introspection: default-deny route guards, Express 4 adapter, st-gateway lane policy (package.json:4; src/index.ts:3-15; README.md:21).
2. Entry points (library, no HTTP routes; CJS main dist/index.js + types, package.json:16-17; engines node>=18, :19-21):
 - createAuthorizer, createIntrospector, splitScopes, soleAuthorizationLine, authorizationLines, bearerFrom, isSafeMethod (src/index.ts:27-36)
 - createExpressAuth (requireScope/requireSession/allowPublic/ignoreCredentials/guard, src/express.ts:884-944), secured (throws at registration if a route lacks a declaration), passthrough, notFound, actorOf/identityOf/kindOf/hasScope/requirementOf, CREDENTIALS_IGNORED (src/index.ts:62-73)
 - createLaneDeriver (st-gateway lane; never rejects/throws) (src/index.ts:39; src/gateway.ts:4-9,36-66)
 - loadIntrospectionConfig, IntrospectionConfigError: env AUTH_INTROSPECTION_URL + AUTH_INTROSPECTION_SECRET (src/messages.ts:35,38; src/config.ts:44-45); full endpoint, http/https only, no query, needs global fetch (src/config.ts:37-39,56-81)
 - createCentralM2MTokenSource, M2MTokenError (src/index.ts:76)
3. Unauthenticated routes: none served by library. Public-route spellings it gives consumers:
 - allowPublic() = "none"; on a non-safe method answers 500 (src/express.ts:1113; src/core.ts:340)
 - ignoreCredentials(): registration refused except get/head/options/use (src/express.ts:605-632); non-safe method reaching it via use() -> 500 (:1076-1081)
 - notFound(): only as sole `use(notFound(h))`, last, status clamped >=400 (src/express.ts:415-459,661-686); arity-4 error handlers need no declaration (:718); passthrough() items may precede declaration (:574-577)
 - Undeclared/resolver-miss -> 500 on every method (src/express.ts:1027-1037); app.del refused (:827-835); app.get("x") one-string = settings getter, not a route (:800)
 - st-gateway does not secure its app; /proxy forwards anonymous mutations by design (README.md:337-345)
4. Money/spend: none. No SpaceTraders or paid-API calls; only fetch calls go to auth-service (src/center.ts:176; src/m2mToken.ts:153,175).
5. Calls out / called by:
 - POST form `token=...` to AUTH_INTROSPECTION_URL (e.g. /auth/v1/introspect), header X-Introspection-Secret, redirect manual, timeout 1000ms, 64KiB cap (src/center.ts:176-195; src/messages.ts:32,41,44)
 - POST to auth-service m2m-token URL (e.g. /auth/v1/m2m-token), header X-M2M-Caller-Secret, timeout 1000ms (src/m2mToken.ts:22,24,61,175-178)
 - Consumers on 2.0.1 tarball: agent-service (package.json:24), automation-service (:19), fleet-service (:20), st-gateway (:18). ai-service still on old @v-m-pioneer-trading/introspection-client v1.2.0 from old repo URL (../ai-service/package.json:17). README says three (README.md:9-10), stale.
 - Usage: st-gateway createLaneDeriver (../st-gateway/src/server.ts:189); automation-service createCentralM2MTokenSource (../automation-service/src/config.ts:90). Gateway should pass timeoutMs:250 (README.md:347)
 - Vendored fixture: test/fixtures/introspection.json from meta fixtures/introspection.json, v7, commit f226e5f4, 75 cases, sha256 95cb78d8 (test/fixtures/SOURCE:3-10); test/conformance.test.ts:62 checks copy vs SOURCE, :76,:138 sorted case names. Re-vendor steps SOURCE:33-39.
 - Dev dep eslint-config pinned by release tarball URL v1.1.0 (package.json:35)
6. Build/test/run (package.json:22-29): npm ci; build (tsc -p tsconfig.build.json); typecheck (tsc -p tsconfig.json --noEmit); test (jest, ts-jest preset, node env, jest.config.js:3-4); lint (eslint . --max-warnings 0); check:readme (compiles and RUNS every README snippet, scripts/check-readme.mjs:1-26). No run target. .gitignore: node_modules, dist, coverage, .readme-check, *.tgz, *.log (.gitignore:1-6); no .env.example.
7. CI (.github/workflows/ci.yml): on pull_request (any base) + push main (:7-9); permissions contents: read (:14-15). Job test, ubuntu-latest (:18-19); checkout + setup-node SHA-pinned, node 22, cache npm (:26-31). Steps in order:
 npm ci :33; npm run lint :37; npm run typecheck :41; npm run build :43; npm test :45; npm run check:readme :53; pack + tarball content check :57; install tarball in /tmp/consumer CJS project, require-exports probe, core tsc skipLibCheck:false without @types/express :88; Express consumer typecheck :154; startup-registration probe :262; generated-router runtime probe :315; two-Authorization-lines probe :419; duplicate-key probe :576. No AWS or secrets.
 Release (.github/workflows/release.yml): on push tag v* (:8-10); workflow contents: read (:12-13), job contents: write (:21-22); SHA-pinned checkout/setup-node node 22 (:28-33). Steps: tag must equal package.json version (:35-42); npm ci :44; typecheck :46; build :48; npm test :50; npm pack + tar -tzf (:52-59); `gh release create "$GITHUB_REF_NAME" "$TARBALL" --repo --title --generate-notes` with GH_TOKEN=github.token (:61-74). No npm registry publish (:3-7).
8. Persistence/migrations: none. Introspection answer memoized per request only (WeakMap on res, keyed by SHA-256 of header), never across requests (src/express.ts:169-178,1000-1008; README.md:124-135); center client has no cache (src/center.ts:189-193). M2M token cached in memory, refresh at half-life (src/m2mToken.ts:10-15).
9. Patterns:
 - Default deny: every route declares at registration, declaration first, exactly one; secured() throws otherwise (src/express.ts:544-598; src/index.ts:11-12)
 - Non-2xx = unavailable, decided before reading body (src/center.ts:197-203; test/non-2xx.test.ts)
 - Token in POST body, never URL (src/center.ts:183-185); strict JSON, duplicate key = malformed (:214-226)
 - Two Authorization lines never a credential (README.md:137; src/express.ts:1159)
 - Express types declared locally; no peer deps (README.md:21-23; src/express.ts:4-11,88)
 - Behaviour change starts in meta fixture, then re-vendor (test/fixtures/SOURCE:38-39)
 - Tests via stub center: test/support/stubCenter.ts:79
10. Traps:
 - Consumers pin release tarball URL (README.md:30) with integrity in package-lock (README.md:24-27). Not on npm; bump = new tag + release + edit each consumer URL/lock.
 - Tag vX.Y.Z must equal package.json version or release fails (.github/workflows/release.yml:35-42).
 - README snippets run in CI; README edit can fail check:readme (.github/workflows/ci.yml:46-53).
 - Conformance fails if meta fixture gains a case until implemented (test/fixtures/SOURCE:41-42).
 - Repo/package name (clerk-client) differs from local folder ts-introspection-client; ai-service still pins old name/repo (../ai-service/package.json:17).
 - prepack runs build (package.json:28); files = dist, README, LICENSE only (:18; .github/workflows/ci.yml:57-83).
 - Registry WeakMaps assume one package copy per process (src/express.ts:283-287).
 - Duplicate-Authorization check depends on the header limit 2 x maxHeadersCount; at or past it the request is refused. Set server.maxHeadersCount before the first connection opens (src/core.ts:174,236-248; README.md:155-176).
 - Always give ignoreCredentials()/allowPublic() mounts a path: a pathless mount matches every request and 500s every write routed past it (src/express.ts:905-908; README.md:294-300).
 - A generated (tsoa) router is guarded at mount by the router-level guard, checked only at runtime: do not secured() it, do not mount it bare (src/express.ts:681,931-932; README.md:302-317).
 - M2M token source: unknown-caller is always thrown even with a valid cached token; after any failed refresh no new request for 10 s; the only retry is one on timeout (src/m2mToken.ts:28,220-243; README.md:455-464).
11. Other docs: README.md (usage, migration, releasing at :660-663), CHANGELOG.md, test/fixtures/SOURCE (vendoring record), LICENSE (MIT).

## Reference docs

- README.md: read when changing guard behaviour or a consumer's declarations (Declaration and Behaviour tables, evaluation-ordered rows).
