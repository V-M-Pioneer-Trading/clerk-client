/**
 * @file Caller side of auth-service's machine-token endpoint.
 *
 * A headless service that needs a bearer token of its own asks the center for
 * one (auth-design.md decision 22; the contract is the "Minting a machine
 * token" section of token-introspection.md). This is the port of
 * automation-service's `createClerkM2MTokenSource`, with the Clerk call
 * replaced by one `POST` to the center.
 *
 * The token is cached in memory only and refreshed at `iat + (exp - iat) / 2`,
 * read from the JWT itself, unverified: the center is trusted and the
 * receiving service verifies nothing either, it introspects. A failed refresh
 * is not repeated for {@link FAILURE_SPACING_MS}, matching the center's own
 * spacing between failed mints; meanwhile a cached token that has not expired
 * is served at once.
 *
 * Every failure is an {@link M2MTokenError}. Neither the secret nor the token
 * is ever logged or placed in an error.
 */

/** The header the contract names. Not the introspection one. */
const M2M_SECRET_HEADER = "X-M2M-Caller-Secret";

const DEFAULT_M2M_TIMEOUT_MS = 1000;
const MAX_TIMEOUT_MS = 2 ** 31 - 1;

/** After a failed refresh, do not ask again for this long. */
const FAILURE_SPACING_MS = 10_000;

/** The contract's token lives 24 h; anything past a week is not this center. */
const MAX_LIFETIME_SECONDS = 7 * 24 * 60 * 60;

/**
 * - `unknown-caller`: the center answered 401. A configuration error; exit.
 * - `unavailable`: transport failure, timeout, 503 or any other status. Log,
 *   continue, try again later.
 * - `malformed`: the answer arrived but its body or token is unusable.
 */
export type M2MTokenErrorKind = "unknown-caller" | "unavailable" | "malformed";

export class M2MTokenError extends Error {
  readonly kind: M2MTokenErrorKind;

  /**
   * @param cause For a transport failure, only `{ code?, name? }` taken from
   *   the underlying error and checked to be short identifiers. Never a body,
   *   the secret or a token.
   */
  constructor(kind: M2MTokenErrorKind, message: string, cause?: { code?: string; name?: string }) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "M2MTokenError";
    this.kind = kind;
  }
}

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
  /** Per-attempt timeout, a positive integer no larger than 2^31-1. Defaults to 1000. */
  timeoutMs?: number;
}

interface CachedToken {
  token: string;
  expiresAtMs: number;
  refreshAtMs: number;
}

/** Errors that came from a timeout, the only thing retried. */
const timeouts = new WeakSet<M2MTokenError>();

const IDENTIFIER = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

/** Only a short identifier survives; anything else could carry data. */
const safeIdentifier = (value: unknown): string | undefined =>
  typeof value === "string" && IDENTIFIER.test(value) ? value : undefined;

const isTimeout = (err: unknown): boolean =>
  err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");

const transportCause = (err: unknown): { code?: string; name?: string } => {
  const out: { code?: string; name?: string } = {};
  const holder = (typeof err === "object" && err !== null ? err : {}) as {
    code?: unknown;
    name?: unknown;
    cause?: unknown;
  };
  const inner = (typeof holder.cause === "object" && holder.cause !== null ? holder.cause : {}) as {
    code?: unknown;
  };
  const code = safeIdentifier(holder.code) ?? safeIdentifier(inner.code);
  const name = safeIdentifier(holder.name);
  if (code !== undefined) out.code = code;
  if (name !== undefined) out.name = name;
  return out;
};

const malformed = (what: string): M2MTokenError =>
  // Deliberately not echoing any part of the answer.
  new M2MTokenError("malformed", `the authentication service returned ${what}`);

const cacheFrom = (token: string, nowMs: number): CachedToken => {
  let payload: unknown;
  try {
    const segment = token.split(".")[1];
    payload = JSON.parse(Buffer.from(segment ?? "", "base64url").toString("utf8"));
  } catch {
    payload = null;
  }
  const claims = (typeof payload === "object" && payload !== null ? payload : {}) as Record<string, unknown>;
  const { iat, exp } = claims;
  if (typeof iat !== "number" || typeof exp !== "number" || !Number.isFinite(iat) || !Number.isFinite(exp)) {
    throw malformed("a machine token without a usable lifetime");
  }
  if (!(exp > iat) || exp - iat > MAX_LIFETIME_SECONDS) {
    throw malformed("a machine token with an implausible lifetime");
  }
  if (nowMs >= exp * 1000) {
    throw malformed("a machine token that has already expired");
  }
  return { token, expiresAtMs: exp * 1000, refreshAtMs: (iat + (exp - iat) / 2) * 1000 };
};

const validate = (options: CentralM2MTokenOptions): number => {
  if (typeof options.url !== "string" || options.url.trim() === "") {
    throw new TypeError("createCentralM2MTokenSource: url must be a non-empty string");
  }
  if (typeof options.secret !== "string" || options.secret === "" || /[\r\n]/.test(options.secret)) {
    // Never echoes the secret.
    throw new TypeError("createCentralM2MTokenSource: secret must be a non-empty string without CR or LF");
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_M2M_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new RangeError(
      "createCentralM2MTokenSource: timeoutMs must be a positive integer no larger than 2147483647"
    );
  }
  return timeoutMs;
};

export function createCentralM2MTokenSource(options: CentralM2MTokenOptions): M2MTokenSource {
  const timeoutMs = validate(options);
  const doFetch = options.fetch ?? ((...args: Parameters<typeof fetch>) => globalThis.fetch(...args));
  const now = options.now ?? Date.now;

  let cached: CachedToken | null = null;
  let inflight: Promise<string> | null = null;
  let failure: { error: M2MTokenError; untilMs: number } | null = null;

  const timedOut = (): M2MTokenError => {
    const err = new M2MTokenError(
      "unavailable",
      "the authentication service did not answer the token request in time",
      { name: "TimeoutError" }
    );
    timeouts.add(err);
    return err;
  };

  const attempt = async (): Promise<CachedToken> => {
    // One signal covers the headers and the body read.
    const signal = AbortSignal.timeout(timeoutMs);
    let res: Response;
    try {
      res = await doFetch(options.url, {
        method: "POST",
        headers: { [M2M_SECRET_HEADER]: options.secret },
        signal,
      });
    } catch (err) {
      if (isTimeout(err)) throw timedOut();
      throw new M2MTokenError(
        "unavailable",
        "the token request to the authentication service failed",
        transportCause(err)
      );
    }
    if (res.status !== 200) {
      void res.body?.cancel().catch(() => undefined);
      if (res.status === 401) {
        throw new M2MTokenError(
          "unknown-caller",
          "the authentication service did not recognise this caller (401): check this service's machine-token secret"
        );
      }
      if (res.status === 503) {
        throw new M2MTokenError("unavailable", "the authentication service could not mint a token (503)");
      }
      throw new M2MTokenError(
        "unavailable",
        `the authentication service answered the token request with status ${res.status}`
      );
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch (err) {
      if (isTimeout(err)) throw timedOut();
      throw malformed("an unreadable token answer");
    }
    const token = typeof body === "object" && body !== null ? (body as { token?: unknown }).token : undefined;
    if (typeof token !== "string" || token === "") {
      throw malformed("a token answer without a token");
    }
    return cacheFrom(token, now());
  };

  const mint = async (): Promise<string> => {
    try {
      let result: CachedToken;
      try {
        result = await attempt();
      } catch (err) {
        // A timeout is the one thing retried: the first mint after an
        // auth-service restart is the slow answer, and the retry joins it.
        if (!(err instanceof M2MTokenError) || !timeouts.has(err)) throw err;
        result = await attempt();
      }
      cached = result;
      failure = null;
      return result.token;
    } catch (err) {
      const error =
        err instanceof M2MTokenError ? err : new M2MTokenError("unavailable", "the token request failed unexpectedly");
      failure = { error, untilMs: now() + FAILURE_SPACING_MS };
      throw error;
    }
  };

  /** What to do with a failed or suppressed refresh. */
  const fallback = (error: M2MTokenError): string => {
    // A wrong secret is a configuration error and must never be masked.
    if (error.kind === "unknown-caller") throw error;
    if (cached !== null && now() < cached.expiresAtMs) return cached.token;
    throw error;
  };

  return {
    async getToken(): Promise<string> {
      const t = now();
      if (cached !== null && t < cached.refreshAtMs) return cached.token;

      if (inflight === null) {
        if (failure !== null && t < failure.untilMs) return fallback(failure.error);
        inflight = mint().finally(() => {
          inflight = null;
        });
      }
      try {
        return await inflight;
      } catch (err) {
        return fallback(err as M2MTokenError);
      }
    },
  };
}
