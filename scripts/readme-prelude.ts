/**
 * @file The free identifiers the README's snippets name.
 *
 * A README snippet is written for a reader, so it says `listTargets` and
 * `RegisterRoutes` and `swaggerUi` without defining them. To RUN one, those
 * have to be something — and what they are matters: `RegisterRoutes` really
 * registers routes onto the router it is handed, `swaggerUi.serve` really is
 * an array of middleware, and `auth` is a real `createExpressAuth` over a
 * center nothing is listening on. Stubs that were merely typed would let the
 * snippet compile and prove nothing about what `secured()` does with it.
 *
 * This file is copied into `.readme-check/prelude.ts` by
 * `scripts/check-readme.mjs`, which is why its imports are relative to that
 * directory.
 */

import express from "express";

import {
  actorOf,
  authorizationLines,
  createAuthorizer,
  createExpressAuth,
  createLaneDeriver,
  hasScope,
  identityOf,
  kindOf,
  loadIntrospectionConfig,
  notFound,
  passthrough,
  requirementOf,
  secured,
} from "../src/index";
import type { NextLike, RequestLike, ResponseLike } from "../src/express";

const config = {
  url: "http://127.0.0.1:59999/auth/v1/introspect",
  secret: "readme-check-secret",
};

/** A handler of the shape every snippet's named handler has. */
const handler = (_req: RequestLike, res: ResponseLike): void => {
  res.status(200).json({ ok: true });
};

/** tsoa's generated entry point: it really does register routes. */
const RegisterRoutes = (router: express.Router): void => {
  router.get("/ships", (_req, res) => {
    res.json({ ships: [] });
  });
  router.post("/ships/:id/navigate", (_req, res) => {
    res.json({ navigating: true });
  });
};

/** `swaggerUi.serve` is an ARRAY of middleware; `setup()` returns one handler. */
const swaggerUi = {
  serve: [
    (_req: RequestLike, _res: ResponseLike, next: NextLike): void => next(),
    (_req: RequestLike, _res: ResponseLike, next: NextLike): void => next(),
  ],
  setup: (_spec: unknown) => handler,
};

const cors = (_options?: unknown) => (
  _req: RequestLike,
  _res: ResponseLike,
  next: NextLike
): void => next();

/**
 * A request double, for the snippets that read one header off it and count
 * its raw lines.
 *
 * `header()` is typed as a real Express `Request` types it for a name other
 * than `set-cookie` — `string | undefined`, not the `string[]` union — and
 * `rawHeaders` as the mutable `string[]` Node declares, because the snippet
 * is a claim about what a consumer's own code compiles to.
 */
const req: {
  readonly method: string;
  readonly rawHeaders: string[];
  header(name: string): string | undefined;
} = {
  method: "GET",
  rawHeaders: ["Host", "localhost"],
  header: (_name: string): string | undefined => undefined,
};

export const prelude = () => ({
  express,
  cors,
  corsOptions: { origin: "https://example.test" },
  swaggerUi,
  spec: { openapi: "3.0.0" },
  assetDir: __dirname,
  proxy: handler,
  health: handler,
  listTargets: handler,
  navigate: handler,
  listShips: handler,
  RegisterRoutes,
  auth: createExpressAuth(config),
  config,
  req,
  actorOf,
  authorizationLines,
  identityOf,
  kindOf,
  hasScope,
  requirementOf,
  createAuthorizer,
  createExpressAuth,
  createLaneDeriver,
  loadIntrospectionConfig,
  notFound,
  passthrough,
  secured,
});
