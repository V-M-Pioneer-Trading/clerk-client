/**
 * @file A non-2xx answer is unavailable whatever its body says (meta fixture
 * version 7, clerk-client#13).
 *
 * Every non-2xx case before version 7 carried an error body that no reader
 * takes for an answer, so the early `if (!response.ok)` return in
 * src/center.ts could be deleted with the whole suite still green: the body
 * failed to parse, or parsed to something that was not an active answer, and
 * the 503 came out anyway. Here the body is a valid active answer for an
 * operator holding the required scope, so only the status check stands
 * between it and `proceed` (or the interactive lane).
 */

import express from "express";
import request from "supertest";

import { createIntrospector } from "../src/center";
import { createAuthorizer } from "../src/core";
import { createExpressAuth, identityOf, secured } from "../src/express";
import { createLaneDeriver } from "../src/gateway";
import { MESSAGES } from "../src/messages";
import { loadFixture } from "./support/fixture";
import { startStubCenter } from "./support/stubCenter";

const SECRET = "non-2xx-suite-secret";
const TOKEN = "non2xx.token.suite";

/** A valid active answer that satisfies `fleet:control`, and a session route. */
const ACTIVE =
  '{"active":true,"sub":"user_a","scope":"fleet:control","exp":4102444800,"kind":"operator"}';

const UNAVAILABLE = {
  outcome: "reject",
  status: 503,
  message: MESSAGES.centerUnavailable,
} as const;

/** The five the fixture pins, and the rest of the ranges a client might special-case. */
const STATUSES = [500, 401, 302, 503, 404, 301, 303, 307, 308, 400, 403, 409, 418, 429, 502, 504];

const withCenter = async <T>(status: number, body: string, run: (url: string) => Promise<T>) => {
  const center = await startStubCenter({ status, body });
  try {
    const result = await run(center.url);
    return { result, calls: center.requests.length };
  } finally {
    await center.close();
  }
};

describe("the control: the same body with a 200 is read", () => {
  it("proceeds, so every refusal below is the status's doing", async () => {
    const { result } = await withCenter(200, ACTIVE, (url) =>
      createAuthorizer({ url, secret: SECRET }).authorize({
        method: "POST",
        requires: "fleet:control",
        authorization: `Bearer ${TOKEN}`,
      })
    );
    expect(result).toEqual({
      outcome: "proceed",
      identity: { sub: "user_a", kind: "operator", scopes: ["fleet:control"] },
    });
  });

  it("lanes interactive at the gateway", async () => {
    const { result } = await withCenter(200, ACTIVE, (url) =>
      createLaneDeriver({ url, secret: SECRET }).derive(`Bearer ${TOKEN}`)
    );
    expect(result).toBe("interactive");
  });
});

describe.each(STATUSES)("the center answers %i with an active body", (status) => {
  it("the introspector reports it unavailable", async () => {
    const { result, calls } = await withCenter(status, ACTIVE, (url) =>
      createIntrospector({ url, secret: SECRET }).introspect(TOKEN)
    );
    expect(result).toEqual({ state: "unavailable" });
    expect(calls).toBe(1);
  });

  it.each([
    ["a scoped POST", "POST", "fleet:control"],
    ["a session GET", "GET", "session"],
    ["a public GET carrying a token", "GET", "none"],
  ])("%s answers 503, never proceed", async (_label, method, requires) => {
    const { result, calls } = await withCenter(status, ACTIVE, (url) =>
      createAuthorizer({ url, secret: SECRET }).authorize({
        method,
        requires,
        authorization: `Bearer ${TOKEN}`,
      })
    );
    expect(result).toEqual(UNAVAILABLE);
    expect(calls).toBe(1);
  });

  it("the gateway lanes background, never interactive", async () => {
    const { result, calls } = await withCenter(status, ACTIVE, (url) =>
      createLaneDeriver({ url, secret: SECRET }).derive(`Bearer ${TOKEN}`)
    );
    expect(result).toBe("background");
    expect(calls).toBe(1);
  });
});

describe("the fixture's version 7 cases, through the Express adapter consumers use", () => {
  const fixture = loadFixture();
  const calling = fixture.cases.filter((c) => c.name.endsWith("-with-active-body"));
  const gateway = fixture.gatewayCases.filter((c) => c.name.endsWith("-with-active-body"));

  it("are in the vendored fixture, five of each", () => {
    expect(calling.map((c) => c.center.status)).toEqual([500, 401, 302, 503, 404]);
    expect(gateway.map((c) => c.center.status)).toEqual([500, 401, 302, 503, 404]);
  });

  it.each(calling.map((c) => [c.name, c] as const))(
    "%s is 503 through real Express and createExpressAuth",
    async (_name, testCase) => {
      const center = await startStubCenter(testCase.center);
      try {
        const auth = createExpressAuth({ url: center.url, secret: SECRET });
        const api = secured(express.Router());
        api.post("/case", auth.requireScope(testCase.route?.requires ?? ""), (_req, res) => {
          res.json({ identity: identityOf(res) });
        });
        const app = express();
        app.use(api);
        const response = await request(app)
          .post("/case")
          .set("Authorization", testCase.request.authorization as string);
        expect(response.status).toBe(503);
        expect(response.body).toEqual({ error: { message: MESSAGES.centerUnavailable } });
        expect(center.requests).toHaveLength(1);
      } finally {
        await center.close();
      }
    }
  );
});
