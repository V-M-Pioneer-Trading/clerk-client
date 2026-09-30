/**
 * @file Public surface.
 *
 * Three entry points, deliberately separate:
 *
 * - {@link createAuthorizer} — the framework-agnostic policy, the forty
 *   calling-service cases of `meta/fixtures/introspection.json`, given a
 *   caller that applies {@link soleAuthorizationLine}.
 * - {@link createExpressAuth} — the Express 4 adapter over it, whose
 *   declarations live at route registration so Express's own matcher binds
 *   them, and whose {@link secured} wrapper refuses **at startup** to register
 *   a route that carries none.
 * - {@link createLaneDeriver} — st-gateway's lane policy, which never rejects
 *   and is kept apart so nothing adopts it by accident.
 */

export type {
  Decision,
  Identity,
  IntrospectionConfig,
  Kind,
  Lane,
  RouteRequirement,
} from "./types";

export type { CenterAnswer, Introspector } from "./center";
export { createIntrospector, splitScopes } from "./center";

export type { Authorizer, InboundRequest, RawHeaderSource } from "./core";
export {
  authorizationLines,
  bearerFrom,
  createAuthorizer,
  isSafeMethod,
  soleAuthorizationLine,
} from "./core";

export type { LaneDeriver } from "./gateway";
export { createLaneDeriver } from "./gateway";

export { IntrospectionConfigError, loadIntrospectionConfig } from "./config";

export {
  DEFAULT_MAX_RESPONSE_BYTES,
  DEFAULT_TIMEOUT_MS,
  ENV_SECRET,
  ENV_URL,
  MESSAGES,
  SECRET_HEADER,
} from "./messages";

export type {
  DeclaredRequirement,
  ExpressAuth,
  GuardContext,
  HandlerLike,
  NextLike,
  RequestLike,
  RequirementResolver,
  ResponseLike,
} from "./express";
export {
  actorOf,
  createExpressAuth,
  CREDENTIALS_IGNORED,
  hasScope,
  identityOf,
  kindOf,
  notFound,
  passthrough,
  requirementOf,
  secured,
} from "./express";

export type { CentralM2MTokenOptions, M2MTokenErrorKind, M2MTokenSource } from "./m2mToken";
export { createCentralM2MTokenSource, M2MTokenError } from "./m2mToken";
