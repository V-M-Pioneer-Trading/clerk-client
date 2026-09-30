/**
 * @file Caller side of auth-service's machine-token endpoint.
 *
 * A headless service that needs a bearer token of its own asks the center for
 * one (auth-design.md decision 22; the contract is the "Minting a machine
 * token" section of token-introspection.md). This is the port of
 * automation-service's `createClerkM2MTokenSource`, with the Clerk call
 * replaced by one `POST` to the center.
 *
 * The token is cached in memory only, refreshed once half its lifetime (read
 * from the JWT's own `iat`/`exp`, unverified: the center is trusted and the
 * receiving service verifies nothing either, it introspects) has passed, and
 * a stale-but-unexpired token is preferred over a failed refresh.
 *
 * Neither the secret nor the token is ever logged or placed in an error.
 */

/** The same header name the contract gives the center. Not the introspection one. */
const M2M_SECRET_HEADER = "X-Service-Secret";

const DEFAULT_M2M_TIMEOUT_MS = 1000;

/** Refresh once this fraction of the token's lifetime has elapsed. */
const REFRESH_AT_FRACTION = 0.5;

export interface M2MTokenSource {
  getToken(): Promise<string>;
}

export interface CentralM2MTokenOptions {
  /** The center's mint URL, e.g. `http://localhost:3005/auth/v1/m2m-token`. */
  url: string;
  /** This caller's own secret. It is the caller's identity at the center. */
  secret: string;
  /** Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /** Milliseconds since the epoch. Defaults to `Date.now`. */
  now?: () => number;
  /** Per-attempt timeout. Defaults to 1000. */
  timeoutMs?: number;
}

interface CachedToken {
  token: string;
  expiresAtMs: number;
  refreshAtMs: number;
}

/** An attempt that failed in a way worth one more immediate try. */
class RetryableError extends Error {}

const cacheFrom = (token: string): CachedToken => {
  let payload: unknown;
  try {
    const segment = token.split(".")[1];
    payload = JSON.parse(Buffer.from(segment ?? "", "base64url").toString("utf8"));
  } catch {
    payload = null;
  }
  const claims = (typeof payload === "object" && payload !== null ? payload : {}) as Record<string, unknown>;
  const { iat, exp } = claims;
  if (typeof iat !== "number" || typeof exp !== "number" || !(exp > iat)) {
    // Deliberately not echoing any part of the token.
    throw new Error("the authentication service returned a machine token without a usable lifetime");
  }
  return {
    token,
    expiresAtMs: exp * 1000,
    refreshAtMs: (iat + (exp - iat) * REFRESH_AT_FRACTION) * 1000,
  };
};

const isTimeout = (err: unknown): boolean =>
  err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");

export function createCentralM2MTokenSource(options: CentralM2MTokenOptions): M2MTokenSource {
  const doFetch = options.fetch ?? ((...args: Parameters<typeof fetch>) => globalThis.fetch(...args));
  const now = options.now ?? Date.now;
  const timeoutMs = options.timeoutMs ?? DEFAULT_M2M_TIMEOUT_MS;

  let cached: CachedToken | null = null;
  let inflight: Promise<string> | null = null;

  const attempt = async (): Promise<CachedToken> => {
    let res: Response;
    try {
      res = await doFetch(options.url, {
        method: "POST",
        headers: { [M2M_SECRET_HEADER]: options.secret },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      if (isTimeout(err)) throw new RetryableError("the authentication service did not answer the token request in time");
      throw new Error("the token request to the authentication service failed");
    }
    // The body is never needed on a failure; drop it without reading into an error.
    if (res.status === 401) {
      void res.body?.cancel().catch(() => undefined);
      throw new Error(
        "the authentication service did not recognise this caller (401): check this service's machine-token secret"
      );
    }
    if (res.status === 503) {
      void res.body?.cancel().catch(() => undefined);
      throw new RetryableError("the authentication service could not mint a token (503)");
    }
    if (res.status !== 200) {
      void res.body?.cancel().catch(() => undefined);
      throw new Error(`the authentication service answered the token request with status ${res.status}`);
    }
    let token: unknown;
    try {
      ({ token } = (await res.json()) as { token?: unknown });
    } catch {
      throw new Error("the authentication service returned an unreadable token answer");
    }
    if (typeof token !== "string" || token === "") {
      throw new Error("the authentication service returned a token answer without a token");
    }
    return cacheFrom(token);
  };

  const mint = async (): Promise<string> => {
    let result: CachedToken;
    try {
      result = await attempt();
    } catch (err) {
      if (!(err instanceof RetryableError)) throw err;
      // The first mint after an auth-service restart is the one slow answer.
      result = await attempt();
    }
    cached = result;
    return result.token;
  };

  return {
    async getToken(): Promise<string> {
      if (cached !== null && now() < cached.refreshAtMs) return cached.token;

      inflight ??= mint().finally(() => {
        inflight = null;
      });
      try {
        return await inflight;
      } catch (err) {
        if (cached !== null && now() < cached.expiresAtMs) return cached.token;
        throw err;
      }
    },
  };
}
