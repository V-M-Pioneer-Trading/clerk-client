/**
 * @file The one place this package talks to auth-service.
 *
 * One POST, no retries, a hard timeout, no cache, and a body read under a
 * byte cap. Every way of failing collapses to the single `unavailable`
 * answer, because the caller's remedy is identical in all of them and the
 * distinction is the center's own business, in the center's own logs.
 *
 * Nothing here parses, decodes or inspects the token: it is an opaque string
 * that goes into a form body and nothing more (auth-design.md decision 21).
 * Nothing here logs, so neither the token nor the secret can reach a log line.
 */

import {
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_TIMEOUT_MS,
  SECRET_HEADER,
} from "./messages";
import { parseStrictJson } from "./strictJson";
import type { Identity, IntrospectionConfig, Kind } from "./types";

/**
 * What one introspection call learned.
 *
 * `unavailable` deliberately carries no detail. It covers a center that was
 * unreachable, one that timed out, one that answered non-2xx, one whose body
 * did not parse, and one that rejected our own caller secret — and a client
 * that distinguished them would only be tempted to relay the difference.
 */
export type CenterAnswer =
  | { readonly state: "active"; readonly identity: Identity }
  | { readonly state: "inactive" }
  | { readonly state: "unavailable" };

const UNAVAILABLE: CenterAnswer = { state: "unavailable" };
const INACTIVE: CenterAnswer = { state: "inactive" };

/**
 * Split a `scope` string the way all five verifiers live today do
 * (`strings.Fields` in Go, `/\s+/` in TS, `\s+` in Java): on whitespace
 * *runs*, with empties discarded. `scope` is space-delimited by convention,
 * not by guarantee — the center returns the Clerk claim verbatim.
 */
export const splitScopes = (scope: string): string[] =>
  scope.split(/\s+/).filter((s) => s.length > 0);

const isKind = (value: unknown): value is Kind =>
  value === "operator" || value === "machine";

/**
 * Turn a parsed body into an answer, or `null` if it is not the contract.
 *
 * A partial or wrongly typed answer is not `active: false`. Treating it as an
 * inactive token would turn a half-deployed center into a fleet-wide 401 storm
 * and tell operators their credentials were broken when they were not.
 */
const readBody = (body: unknown): CenterAnswer | null => {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const record = body as Record<string, unknown>;

  // Strictly boolean: a truthy 1 or "true" is a center we do not understand.
  if (record.active === false) return INACTIVE;
  if (record.active !== true) return null;

  const { sub, scope, exp, kind } = record;
  if (typeof sub !== "string" || sub.length === 0) return null;
  // RFC 7662 makes `scope` OPTIONAL on an active answer, and auth-service
  // before its PR #4 left the key out for a token carrying no scopes. Absent
  // means "no scopes", exactly as `"scope":""` does; a session route must let
  // that caller through, not answer 503. Present-but-not-a-string is still a
  // center we do not understand (agent-service's Go client draws the same line).
  if (scope !== undefined && typeof scope !== "string") return null;
  if (typeof exp !== "number" || !Number.isFinite(exp)) return null;
  if (!isKind(kind)) return null;

  return {
    state: "active",
    identity: { sub, kind, scopes: splitScopes(scope ?? "") },
  };
};

/** Read at most `limit` bytes of a response, then give up on it. */
const readCapped = async (response: Response, limit: number): Promise<string | null> => {
  const body = response.body;
  if (body === null) return null;

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      size += value.byteLength;
      // An answer larger than the cap is a center we cannot understand, and
      // reading the rest of it only spends memory on the way to the same 503.
      if (size > limit) return null;
      chunks.push(value);
    }
  } finally {
    // Frees the socket whether we finished or bailed out early.
    await reader.cancel().catch(() => undefined);
  }

  const joined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(joined);
};

/** Asks the center about one token. */
export interface Introspector {
  introspect(token: string): Promise<CenterAnswer>;
}

/**
 * Build the client. `config.url` is used verbatim: never joined, never
 * suffixed, never taken apart (token-introspection.md, "Conformance").
 */
export function createIntrospector(config: IntrospectionConfig): Introspector {
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = config.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;

  return {
    async introspect(token: string): Promise<CenterAnswer> {
      const controller = new AbortController();
      // The budget covers the body read as well as the response headers: a
      // center that answers instantly and then dribbles bytes forever is as
      // unavailable as one that never answers.
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        // Resolved per call rather than captured at module load, so a host
        // that installs a fetch of its own is honoured.
        const response = await globalThis.fetch(config.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "application/json",
            [SECRET_HEADER]: config.secret,
          },
          // The token travels in the body. Never in the URL, where it would
          // land in an access log.
          body: `token=${encodeURIComponent(token)}`,
          // Not `follow`: a redirect would carry our caller secret to whatever
          // host the Location header named. A 3xx is simply not a 2xx.
          redirect: "manual",
          // There is no cache here and there is not going to be one: a cached
          // introspection is a second verification path with a different
          // answer, and it makes revocation mean nothing for its lifetime
          // (auth-design.md decision 21). Node's fetch does not cache, so this
          // is a property of the code rather than an option passed to it.
          signal: controller.signal,
        });

        if (!response.ok) {
          // Covers the center's own 401 about OUR secret. Relaying that as a
          // 401 would tell an operator to sign in again, forever, against a
          // service that can never accept them.
          await response.body?.cancel().catch(() => undefined);
          return UNAVAILABLE;
        }

        // readCapped decodes the bytes before the reader below sees them, so a
        // leading UTF-8 BOM is stripped and invalid UTF-8 becomes U+FFFD.
        // Jackson refuses invalid UTF-8 and Go refuses a BOM, so both bodies
        // are read here where the Java or Go client answers 503. A known
        // difference, left as it is: neither can come from the center, which
        // marshals a struct.
        const text = await readCapped(response, maxBytes);
        if (text === null) return UNAVAILABLE;

        // Strict, not JSON.parse: a key named twice in any object is a
        // malformed answer (meta fixture v5, ts-introspection-client#6).
        // JSON.parse lets the last value win, so {"sub":"a","sub":"b"} would
        // proceed as b where the Java client (Jackson,
        // STRICT_DUPLICATE_DETECTION, any depth) and the Go client (top-level
        // members) refuse the body. The cap above runs first, so the parser
        // never sees more than maxResponseBytes.
        let parsed: unknown;
        try {
          parsed = parseStrictJson(text);
        } catch {
          return UNAVAILABLE;
        }
        return readBody(parsed) ?? UNAVAILABLE;
      } catch {
        // Timeout, connection refused, DNS failure, a socket that died
        // mid-body. The error is swallowed rather than wrapped: it can carry
        // the URL, and nothing upstream is allowed to render it anyway.
        return UNAVAILABLE;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
