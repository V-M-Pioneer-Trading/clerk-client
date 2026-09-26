/**
 * @file st-gateway's lane policy. A separate export on purpose.
 *
 * The gateway does not authorize anything — that already happened, once, in
 * the calling service — so it never rejects, never answers 503 and never
 * throws. Anything other than an active `operator` is `background`, including
 * a center that does not answer: a gateway that failed closed on the center
 * would take the public read surface down with auth-service, which is exactly
 * what the calling-service policy is written to avoid.
 *
 * It is a separate entry point rather than an option on the authorizer so that
 * nothing copies it by accident.
 */

import type { Introspector } from "./center";
import { createIntrospector } from "./center";
import { bearerFrom } from "./core";
import type { IntrospectionConfig, Lane } from "./types";

/** Picks a queue lane for one inbound request. Never rejects it. */
export interface LaneDeriver {
  /**
   * `authorizationHeader` is one header VALUE, so it cannot show that the
   * request carried two `Authorization` lines — Node keeps the first and drops
   * the rest. The caller applies the line-count rule before calling, and
   * passes `null` for more than one line:
   *
   * ```ts
   * deriver.derive(authorizationLines(req.rawHeaders) > 1 ? null : req.header("Authorization"));
   * ```
   *
   * Without it a caller picks which of two credentials decides the lane.
   */
  derive(authorizationHeader: string | null | undefined): Promise<Lane>;
}

export function createLaneDeriver(
  source: IntrospectionConfig | Introspector
): LaneDeriver {
  const introspector: Introspector =
    "introspect" in source ? source : createIntrospector(source);

  return {
    async derive(authorizationHeader): Promise<Lane> {
      const token = bearerFrom(authorizationHeader);
      // No credential, or a scheme that is not bearer: nothing to introspect,
      // and the center must not be on the hot path of the public map.
      if (token === null) return "background";

      try {
        const answer = await introspector.introspect(token);
        // The lane follows `kind`, never the `sub` prefix. That is the whole
        // migration: after decision 21 the center is the one place Clerk's
        // subject conventions are known.
        return answer.state === "active" && answer.identity.kind === "operator"
          ? "interactive"
          : "background";
      } catch {
        // The introspector already collapses every failure to `unavailable`,
        // so this is unreachable in practice. It is here because "never
        // throws" is the contract, and a host that injects its own
        // introspector is not bound by ours.
        return "background";
      }
    },
  };
}
