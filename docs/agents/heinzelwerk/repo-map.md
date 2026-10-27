# Repo map: ts-introspection-client (GitHub: V-M-Pioneer-Trading/clerk-client)

`@v-m-pioneer-trading/clerk-client` 2.x: asks the center (auth-service) what a token carries, default-deny route guards, an Express 4 adapter, st-gateway's lane policy, and an M2M token source. Zero runtime deps, CJS + `.d.ts`. Renamed from introspection-client in 2.0.0; the local folder kept the old name.

| Path | Holds |
|---|---|
| `src/index.ts` | public exports |
| `src/center.ts`, `src/core.ts` | introspection call (`AUTH_INTROSPECTION_URL`, full URL, sent verbatim), verdicts |
| `src/express.ts` | adapter; a declaration is the route's first handler |
| `src/gateway.ts` | lane deriver used by st-gateway |
| `src/m2mToken.ts` | M2M source (`X-M2M-Caller-Secret`); 401 / 503 never retried |
| `src/strictJson.ts`, `src/messages.ts`, `src/types.ts`, `src/config.ts` | |
| `test/fixtures/introspection.json` | vendored meta fixture |
| `scripts/` | README check |

- CI `ci.yml`: lint, typecheck, build, test, `check:readme`, then tarball proofs in scratch projects. `release.yml`: on `v*` matching `package.json`, `gh release create`.
- Consumers: agent-service, automation-service, fleet-service, st-gateway (2.0.1), by tarball URL.

## Reference docs

- `README.md` "Security model", env table, "Minting a machine token": read when changing guards, declarations, the center call or the M2M source.
- `README.md` "Development": read when re-vendoring the fixture or releasing.
