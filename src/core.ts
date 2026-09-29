/**
 * @file The policy, with no framework anywhere near it.
 *
 * This is the calling-service cases of `meta/fixtures/introspection.json` and
 * nothing else — all forty, the three with two `Authorization` lines once the
 * caller has counted them (see {@link authorizationLines}). The Express adapter is
 * a thin translation on top; a `mux` wrapper or a servlet filter would be
 * another. What is fixed is the answer, the request to the center and the call
 * count — everything the fixture can observe from outside.
 */

import type { CenterAnswer, Introspector } from "./center";
import { createIntrospector } from "./center";
import { MESSAGES } from "./messages";
import type { Decision, IntrospectionConfig, RouteRequirement } from "./types";

/**
 * The methods RFC 9110 §9.2.1 calls **safe**: they are not expected to change
 * anything, so default-deny does not apply to them (owner's delegate,
 * 2026-09-21).
 *
 * `HEAD` is here because it is the *same route* as `GET` — Express dispatches
 * it to the `GET` handler — so refusing it would refuse the cheap form of a
 * page already served anonymously. `OPTIONS` is here because a CORS preflight
 * carries no `Authorization` header by definition and a 500 there breaks every
 * cross-origin call before the real request is sent.
 *
 * This exempts them from **default-deny only**. A safe method on a route that
 * *did* declare a requirement is enforced exactly as any other method is: a
 * `HEAD` with no credential on a guarded route is still a 401.
 */
const SAFE_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * True for `GET`, `HEAD` and `OPTIONS`, compared case-insensitively.
 *
 * Case-insensitively because HTTP method tokens are case-sensitive on the wire
 * but a framework may hand us whatever it parsed, and a client that compared
 * case-sensitively would treat `get` as a mutation. Scope comparison, by
 * contrast, is exact and case-sensitive: see {@link decideFrom}.
 */
export const isSafeMethod = (method: string): boolean =>
  SAFE_METHODS.has(method.toUpperCase());

/** One inbound request, reduced to the three things the policy reads. */
export interface InboundRequest {
  /**
   * The HTTP method, any case. Only the safe methods — `GET`, `HEAD` and
   * `OPTIONS` — are exempt from default-deny.
   */
  readonly method: string;
  /** What the route declares it needs. */
  readonly requires: RouteRequirement;
  /**
   * The raw `Authorization` header, or null/undefined when absent — and null
   * unless the request carried exactly one `Authorization` line, which this
   * string cannot show: see {@link authorizationLines}.
   */
  readonly authorization?: string | null;
}

/**
 * Pull the bearer token out of an `Authorization` header.
 *
 * The scheme is matched case-insensitively and anything else — `Basic …`, a
 * bare token, an empty value — reads as no credential at all, exactly as all
 * five verifiers live today do. Forwarding a non-bearer value to the center
 * would turn a 401 into a 503 the first time the center was slow.
 *
 * The header must be **exactly two** whitespace-separated parts. RFC 6750
 * credentials are `Bearer` plus one `token68`, so anything else is malformed
 * and is not repaired:
 *
 * - `"Bearer"` and `"Bearer "` carry no token, and are not an empty token to
 *   ask the center about.
 * - `"Bearer abc def"` is not the token `abcdef`. A header is never
 *   concatenated into a token — joining the remainder invents a credential
 *   nobody issued and sends it to the center.
 * - `"Bearer a, Bearer b"` — a value that already carries two credentials,
 *   folded into one line by a proxy — is four parts and reads as no
 *   credential. Picking one of them would let a caller choose which of two
 *   credentials a service verifies.
 *
 * **Two `Authorization` request headers do not produce that value, and this
 * function cannot see them.** Node's parser does not join repeats of
 * `Authorization`: it is on the list of single-value headers it discards
 * duplicates of, so `req.headers.authorization` — and therefore
 * `req.header("Authorization")` — is the **first** line and the second is
 * dropped before any of this runs. Handed that value, this function reads the
 * first credential as a credential. The line count has to be taken from the
 * request's raw headers **before** the value gets here: see
 * {@link authorizationLines}, which the Express adapter applies and a caller of
 * {@link createAuthorizer} or `createLaneDeriver` must apply itself. Verified
 * on the wire in `credential.test.ts` rather than assumed. The joined shape is
 * still handled here because a proxy or a framework may fold one, and an array
 * (the shape a framework may hand back for a repeated header) is joined the
 * way Node joins a repeatable header and then fails the same count check.
 */
export const bearerFrom = (
  header: string | readonly string[] | null | undefined
): string | null => {
  if (header === null || header === undefined) return null;
  const raw = Array.isArray(header) ? header.join(", ") : (header as string);
  const parts = raw.trim().split(/\s+/);
  if (parts.length !== 2) return null;
  const [scheme, token] = parts as [string, string];
  if (scheme.toLowerCase() !== "bearer") return null;
  // Belt and braces, and known to be so: the length check is unreachable as
  // written, because splitting a TRIMMED non-empty string on whitespace runs
  // cannot produce an empty part, so `parts.length === 2` already guarantees
  // both are non-empty. `"Bearer "` trims to `"Bearer"` and fails the count
  // above instead. A mutation that drops it therefore survives the suite, and
  // that survival is proven equivalence rather than a missing test. It stays
  // because it is the invariant the NEXT edit to the split would break.
  return token.length > 0 ? token : null;
};

/**
 * What {@link authorizationLines} reads off a request: Node's `rawHeaders`,
 * and the socket, for the server's `maxHeadersCount`. A Node
 * `IncomingMessage` and an Express `Request` both satisfy it without a cast.
 */
export interface RawHeaderSource {
  /** Every header line as parsed, alternating name and value. */
  readonly rawHeaders: readonly string[];
  /**
   * The connection. `socket.server.maxHeadersCount` is read if present, and
   * only that; typed `unknown` so nothing here names a Node type.
   */
  readonly socket?: unknown;
}

/** Node's header-pair limit when `server.maxHeadersCount` is left unset. */
const NODE_DEFAULT_RAW_HEADER_ENTRIES = 2000;

/**
 * The server's header-entry limit for this request, or `Infinity` when it has
 * none. Past it Node 22 answers 431 before any handler runs and Node 25 hands
 * the app a truncated `rawHeaders`; the second is why this is read at all.
 *
 * Mirrors Node's own arithmetic: a numeric `server.maxHeadersCount` becomes
 * `maxHeadersCount << 1` entries, and a result `<= 0` (a `0`, a negative, a
 * `NaN`) means no limit; anything else — unset, `null`, no server on the
 * socket — is Node's default of 2000 entries. Assuming the default when the
 * server cannot be seen is the safe direction: a server with a higher limit
 * only has its larger requests refused, never a truncated one trusted.
 */
const rawHeaderEntryCap = (socket: unknown): number => {
  const server =
    typeof socket === "object" && socket !== null
      ? (socket as { readonly server?: unknown }).server
      : undefined;
  const max =
    typeof server === "object" && server !== null
      ? (server as { readonly maxHeadersCount?: unknown }).maxHeadersCount
      : undefined;
  if (typeof max !== "number") return NODE_DEFAULT_RAW_HEADER_ENTRIES;
  const entries = max << 1;
  return entries <= 0 ? Number.POSITIVE_INFINITY : entries;
};

/**
 * How many `Authorization` lines a request carried, counted from Node's
 * `rawHeaders` (alternating name, value; names in whatever case the client
 * sent them, so compared case-insensitively) — or `Infinity` when the count
 * cannot be known.
 *
 * **Exactly one is a credential; anything else is not.** More than one,
 * whatever the values are — two well-formed bearers, a bearer and an empty
 * line, an empty line and a bearer — because Node's parser keeps the *first*
 * `Authorization` line and silently discards the rest, so
 * `req.headers.authorization` alone lets a caller choose which of two
 * credentials gets verified by choosing their order, or with an empty first
 * line turn a credentialed request into an anonymous one. `rawHeaders` is the
 * only place the repeat is still visible.
 *
 * **`Infinity` means "unknowable", and it never reads as one line:**
 *
 * - `rawHeaders` is not an array, has an odd length, or holds a non-string
 *   name. There is nothing trustworthy to count.
 * - `rawHeaders` has reached the server's header limit, `2 × maxHeadersCount`
 *   entries — 2000 by default, roughly five kilobytes of `x:1` filler, far
 *   under `maxHeaderSize`. Past it Node 22 answers `431` before any handler
 *   runs, but Node 25 hands the app a TRUNCATED `rawHeaders` (and `headers`),
 *   so a second `Authorization` line sent after the filler is simply not there
 *   to count. Reading the limit off the server makes the check the same on
 *   every version. Lines are recorded in batches, so a request at the limit
 *   cannot be told from one that went past it, and both are refused.
 *   `server.maxHeadersCount = 0` lifts the limit and this check with it.
 *
 * The Express adapter applies this itself. Anything that hands a header value
 * to {@link createAuthorizer} or to `createLaneDeriver` directly takes it
 * from here, and passes `null` unless the answer is exactly one:
 *
 * ```ts
 * const header = authorizationLines(req) === 1 ? req.header("Authorization") : null;
 * ```
 *
 * It takes the request rather than its `rawHeaders` because the limit lives
 * on the server, and a caller handed only the array could not know it.
 */
export const authorizationLines = (request: RawHeaderSource): number => {
  const rawHeaders: unknown =
    typeof request === "object" && request !== null ? request.rawHeaders : undefined;
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) {
    return Number.POSITIVE_INFINITY;
  }
  if (rawHeaders.length >= rawHeaderEntryCap(request.socket)) {
    return Number.POSITIVE_INFINITY;
  }
  let lines = 0;
  // Names sit at even indices. Stepping by one would count a VALUE that
  // happens to read "authorization" as a line.
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name: unknown = rawHeaders[index];
    if (typeof name !== "string") return Number.POSITIVE_INFINITY;
    if (name.toLowerCase() === "authorization") lines += 1;
  }
  return lines;
};

const reject = (
  status: 401 | 403 | 500 | 503,
  message: string
): Decision => ({ outcome: "reject", status, message });

/** Decides what happens to one inbound request. */
export interface Authorizer {
  authorize(request: InboundRequest): Promise<Decision>;
}

/**
 * Apply the policy to an answer we already have. Split out so the Express
 * adapter and the tests share one copy of the tail of the rules.
 */
const decideFrom = (answer: CenterAnswer, requires: RouteRequirement): Decision => {
  if (answer.state === "unavailable") {
    return reject(503, MESSAGES.centerUnavailable);
  }
  if (answer.state === "inactive") {
    // On every method, including a GET that would have been served
    // anonymously. A bad credential is never downgraded to a visitor.
    return reject(401, MESSAGES.invalidSession);
  }

  const { identity } = answer;
  if (requires === "none" || requires === "session") {
    // `session` is a tier: a verified session carrying no scopes at all is a
    // guest operator who may watch but not act, and is allowed through.
    return { outcome: "proceed", identity };
  }
  // Exact membership, and nothing else: not a prefix, not a namespace walk,
  // not a substring, not a case-fold. `fleet:control:read` does not satisfy
  // `fleet:control`, and neither does `FLEET:CONTROL`.
  if (!identity.scopes.includes(requires)) {
    // 403, not 401 — the session is valid, so re-authenticating would loop.
    // The message must not name the scope.
    return reject(403, MESSAGES.missingScope);
  }
  return { outcome: "proceed", identity };
};

/**
 * Build the authorizer over a live center, or over an injected
 * {@link Introspector} when a host wants to supply its own transport.
 */
export function createAuthorizer(
  source: IntrospectionConfig | Introspector
): Authorizer {
  const introspector: Introspector =
    "introspect" in source ? source : createIntrospector(source);

  return {
    async authorize(request: InboundRequest): Promise<Decision> {
      // Rule order is the rule. Default-deny is settled BEFORE the
      // Authorization header is read, so a valid token, an expired one and
      // none at all all get the same answer: the credential a caller did or
      // did not bring says nothing about a route that declares nothing.
      if (!isSafeMethod(request.method) && request.requires === "none") {
        // 500 and not 403: our own routing-table defect. automation-service
        // maps a 403 to a terminal `credentials` verdict and would abandon a
        // target over a bug the operator can never fix. The center is not
        // called — a route that can never be authorized has nothing to verify.
        return reject(500, MESSAGES.undeclaredRoute);
      }

      const token = bearerFrom(request.authorization);
      if (token === null) {
        if (request.requires === "none") {
          // A safe method with no credential on a route that declares
          // nothing: a public read, or a CORS preflight. Nothing to
          // introspect, so the center is not touched — doing so would put a
          // synchronous dependency in front of every public page load.
          return { outcome: "proceed", identity: null };
        }
        return reject(401, MESSAGES.missingToken);
      }

      return decideFrom(await introspector.introspect(token), request.requires);
    },
  };
}
