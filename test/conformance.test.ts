/**
 * @file All fifty-four conditions of meta's introspection fixture.
 *
 * Driven against a real local HTTP stub, one per case, so that what the client
 * sends is asserted on the wire and not against a mock of itself. Nothing here
 * is hand-written policy: every status, message, identity and call count comes
 * out of the vendored file, and an assertion key this suite does not recognise
 * fails the case rather than being skipped.
 *
 * A case whose `request.authorization` is an ARRAY (version 4) is several
 * `Authorization` lines, and a value cannot carry that: Node keeps the first
 * line and drops the rest before anything reads it. Those cases are therefore
 * sent over HTTP as real, separate header lines — through real Express and
 * `createExpressAuth` for the calling-service cases, and through an Express app
 * applying `soleAuthorizationLine` in front of `createLaneDeriver` for the
 * gateway case, which is the recipe the README gives st-gateway. The receiving
 * server records the lines it saw, so a sender that folded them into one would
 * fail the case rather than pass it by accident. An authorization of any other
 * shape fails the case.
 */

import { request as httpRequest, type IncomingMessage } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import express from "express";

import { createAuthorizer, soleAuthorizationLine } from "../src/core";
import { createExpressAuth, identityOf } from "../src/express";
import { createLaneDeriver } from "../src/gateway";
import {
  DEFAULT_TIMEOUT_MS,
  ENV_SECRET,
  ENV_URL,
  MESSAGES,
  SECRET_HEADER,
} from "../src/messages";
import type { Decision, Identity } from "../src/types";
import {
  assertKnownExpectKeys,
  authorizationShape,
  countFetches,
  fixtureSha256,
  fixtureBytes,
  loadFixture,
  recordedBytes,
  recordedSha256,
  type FixtureCase,
} from "./support/fixture";
import {
  assertKnownCenterKeys,
  startStubCenter,
  type CenterSpec,
  type StubCenter,
} from "./support/stubCenter";

const fixture = loadFixture();

/** The caller secret used throughout, standing in for the SSM value. */
const SECRET = "test-introspection-secret-4f2a";
const ENDPOINT_PATH = "/auth/v1/introspect";

describe("the vendored fixture", () => {
  it("is byte-identical to what SOURCE records", () => {
    expect(fixtureBytes().length).toBe(recordedBytes());
    expect(fixtureSha256()).toBe(recordedSha256());
  });

  it("is the copy this package was written against", () => {
    // Belt and braces: if both the copy and SOURCE were edited together, this
    // literal still pins the bytes the implementation was reviewed against.
    expect(fixtureSha256()).toBe(
      "f12d41d91b12cd4b8d6674a534ad718d90273aaa93becab4e836654467c43c7c"
    );
  });

  it("holds exactly the calling-service cases this suite implements", () => {
    expect(fixture.cases.map((c) => c.name).sort()).toEqual([
      "active-machine-kind",
      "active-with-irregular-scope-whitespace",
      "active-with-multi-value-scope",
      "active-with-non-separators-in-scope",
      "active-with-only-spaces-in-scope",
      "active-with-required-scope",
      "active-with-scope-differing-only-in-case",
      "active-with-scope-that-is-a-prefix-of-required",
      "active-without-required-scope",
      "bearer-with-empty-token",
      "bearer-with-internal-whitespace",
      "center-rejects-our-caller-secret",
      "center-returns-500",
      "center-returns-case-variant-duplicate-key",
      "center-returns-contract-key-in-another-case",
      "center-returns-duplicate-key",
      "center-returns-malformed-json",
      "center-times-out",
      "center-unreachable",
      "head-on-guarded-route-with-no-header",
      "head-on-guarded-route-with-valid-token",
      "head-on-public-get",
      "inactive-token-on-guarded-route",
      "inactive-token-on-public-get",
      "kind-disagrees-with-sub-prefix",
      "lowercase-bearer-scheme",
      "lowercase-route-method",
      "mutating-route-with-no-declared-scope",
      "mutating-route-with-no-declared-scope-and-inactive-token",
      "mutating-route-with-no-declared-scope-and-no-header",
      "no-header-on-guarded-route",
      "non-bearer-scheme-on-guarded-route",
      "operator-on-public-get",
      "options-on-guarded-route-with-no-header",
      "options-with-no-declared-scope",
      "scope-joined-by-em-space",
      "scope-joined-by-form-feed",
      "scope-joined-by-no-break-space",
      "scope-joined-by-several-spaces",
      "scope-joined-by-tab",
      "scope-joined-by-vertical-tab",
      "scoped-route-with-token-lacking-scope-key",
      "session-route-with-inactive-token",
      "session-route-with-no-header",
      "session-route-with-scopeless-token",
      "session-route-with-token-lacking-scope-key",
      "token-on-public-get-while-center-is-down",
      "two-authorization-lines",
      "two-authorization-lines-on-public-get",
      "two-authorization-lines-second-empty",
      "visitor-on-public-get",
    ]);
    expect(fixture.cases).toHaveLength(51);
  });

  it("holds exactly the gateway cases this suite implements", () => {
    expect(fixture.gatewayCases.map((c) => c.name).sort()).toEqual([
      "gateway-active-machine",
      "gateway-active-operator",
      "gateway-active-operator-lacking-scope-key",
      "gateway-bearer-with-empty-token",
      "gateway-center-rejects-our-caller-secret",
      "gateway-center-returns-case-variant-duplicate-key",
      "gateway-center-returns-duplicate-key",
      "gateway-center-unreachable",
      "gateway-inactive-token",
      "gateway-kind-machine-with-user-subject",
      "gateway-kind-operator-with-machine-subject",
      "gateway-no-header",
      "gateway-non-bearer-scheme",
      "gateway-two-authorization-lines",
    ]);
    expect(fixture.gatewayCases).toHaveLength(14);
  });

  it("is fixture version 6, the one that fixes what separates scopes and how keys compare", () => {
    // Version 1 declared default-deny on every non-GET method; version 2
    // exempted the safe methods; version 3 added answers with no `scope` key;
    // version 4 added requests carrying more than one `Authorization` line;
    // version 5 added a center answer that names the same key twice;
    // version 6 pinned that only space, tab, CR and LF separate scopes and
    // that top-level keys equal ignoring case are a duplicate.
    // A copy that fell back would silently stop asserting those cases, which
    // is the drift this number exists to make visible.
    expect(fixture.version).toBe(6);
  });

  it("gives every case an authorization this suite knows how to send", () => {
    // Checked up front as well as per case, so a shape added upstream fails
    // here by name. Anything else is refused rather than sent as no header.
    for (const testCase of [...fixture.cases, ...fixture.gatewayCases]) {
      expect(() => authorizationShape(testCase)).not.toThrow();
    }
    const base = fixture.cases[0];
    if (base === undefined) throw new Error("the fixture has no cases");
    for (const authorization of [["Bearer a"], ["Bearer a", 1], { a: 1 }, 7]) {
      expect(() => authorizationShape({ ...base, request: { authorization } })).toThrow(
        /unknown request.authorization shape/
      );
    }
  });

  it("pins the names the implementation hard-codes", () => {
    expect(fixture.contract.endpoint.method).toBe("POST");
    expect(fixture.contract.endpoint.path).toBe(ENDPOINT_PATH);
    expect(fixture.contract.endpoint.contentType).toBe(
      "application/x-www-form-urlencoded"
    );
    expect(fixture.contract.endpoint.bodyTemplate).toBe("token=<jwt>");
    expect(fixture.contract.endpoint.secretHeader).toBe(SECRET_HEADER);
    expect(fixture.contract.env.url).toBe(ENV_URL);
    expect(fixture.contract.env.secret).toBe(ENV_SECRET);
    expect(fixture.contract.clientTimeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    expect(fixture.contract.retries).toBe(0);
  });

  it("pins the five sentences byte for byte", () => {
    expect(fixture.contract.messages).toEqual({ ...MESSAGES });
  });
});

/** Runs one case against a freshly started stub, and tears it down. */
const withCase = async (
  testCase: FixtureCase,
  run: (stub: StubCenter) => Promise<void>
): Promise<void> => {
  assertKnownExpectKeys(testCase.name, testCase.expect);
  assertKnownCenterKeys(testCase.name, testCase.center);
  const stub = await startStubCenter(testCase.center as CenterSpec);
  try {
    await run(stub);
  } finally {
    await stub.close();
  }
};

/** Assertions shared by both groups: call count, and what went on the wire. */
const assertCenterTraffic = (
  testCase: FixtureCase,
  stub: StubCenter,
  observedCalls: number,
  token: string | null
): void => {
  const expectedCalls = testCase.expect.centerCalls as number;
  expect(observedCalls).toBe(expectedCalls);

  if (testCase.center.transport === undefined) {
    // A reachable stub counts for itself, so the client-side spy and the
    // server-side log have to agree.
    expect(stub.requests).toHaveLength(expectedCalls);
  }

  for (const request of stub.requests) {
    expect(request.method).toBe("POST");
    expect(request.url).toBe(ENDPOINT_PATH);
    // The URL is used verbatim: no path appended, no query string, and above
    // all no token in it, which is where an access log would find it.
    expect(request.url).not.toContain("?");
    if (token !== null) expect(request.url).not.toContain(token);
    expect(request.contentType).toBe("application/x-www-form-urlencoded");
    expect(request.secretHeader).toBe(SECRET);
    expect(request.body).toBe(`token=${encodeURIComponent(token ?? "")}`);
  }

  const expectedRequest = testCase.expect.centerRequest as
    | Record<string, unknown>
    | undefined;
  if (expectedRequest !== undefined) {
    const sent = stub.requests[0];
    expect(sent).toBeDefined();
    expect(sent?.method).toBe(expectedRequest.method);
    expect(sent?.url).toBe(expectedRequest.path);
    expect(sent?.contentType).toBe(expectedRequest.contentType);
    expect(sent?.body).toBe(expectedRequest.body);
    const headers = expectedRequest.headers as Record<string, string>;
    // The fixture writes the value as a placeholder for whatever
    // AUTH_INTROSPECTION_SECRET holds.
    expect(headers[SECRET_HEADER]).toBe(`<${ENV_SECRET}>`);
    expect(sent?.secretHeader).toBe(SECRET);
  }
};

/** The `Authorization` lines a server received, in order, from `rawHeaders`. */
const authorizationLinesSeen = (req: IncomingMessage): string[] => {
  const lines: string[] = [];
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    if (req.rawHeaders[index]?.toLowerCase() === "authorization") {
      lines.push(req.rawHeaders[index + 1] ?? "");
    }
  }
  return lines;
};

/**
 * Send one request whose `Authorization` header is `lines`, one header line
 * each. `http.request` writes an array header value as repeated lines; the
 * receiving server's record of what arrived is what proves it did.
 */
const sendLines = async (
  port: number,
  method: string,
  lines: readonly string[]
): Promise<{ status: number; body: Record<string, unknown> }> => {
  const req = httpRequest({
    host: "127.0.0.1",
    port,
    method,
    path: "/case",
    headers: { connection: "close" },
  });
  // setHeader rather than the options object, whose type pins `authorization`
  // to a single string; at runtime both write an array as repeated lines.
  req.setHeader("Authorization", [...lines]);
  req.end();
  const [res] = (await once(req, "response")) as [IncomingMessage];
  const chunks: Buffer[] = [];
  for await (const chunk of res) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  return {
    status: res.statusCode ?? 0,
    body: text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {},
  };
};

/**
 * A calling-service case whose request carries several `Authorization` lines,
 * run through real Express and the real adapter, and read back as a Decision.
 */
const decideOverTheWire = async (
  testCase: FixtureCase,
  stubUrl: string,
  lines: readonly string[]
): Promise<Decision> => {
  const method = testCase.route?.method ?? "GET";
  if (method.toUpperCase() === "HEAD") {
    throw new Error(`${testCase.name}: a HEAD has no body to read the decision from`);
  }
  const requires = testCase.route?.requires ?? "none";
  const auth = createExpressAuth({ url: stubUrl, secret: SECRET });
  const declaration =
    requires === "none"
      ? auth.allowPublic()
      : requires === "session"
        ? auth.requireSession()
        : auth.requireScope(requires);

  const seen: string[][] = [];
  const app = express();
  app.use((req, _res, next) => {
    seen.push(authorizationLinesSeen(req));
    next();
  });
  app.all("/case", declaration, (_req, res) => {
    res.status(200).json({ identity: identityOf(res) });
  });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const { status, body } = await sendLines(
      (server.address() as AddressInfo).port,
      method,
      lines
    );
    // The lines arrived as lines: as many as the case holds, in its order,
    // empty ones included. A sender that folded them would fail here.
    expect(seen).toEqual([[...lines]]);
    if (status === 200) {
      return { outcome: "proceed", identity: body.identity as Identity | null };
    }
    const error = body.error as { message?: string } | undefined;
    return {
      outcome: "reject",
      status: status as 401 | 403 | 500 | 503,
      message: error?.message ?? `no error envelope on a ${status}`,
    };
  } finally {
    server.closeAllConnections();
    server.close();
    await once(server, "close");
  }
};

/**
 * The gateway case with several `Authorization` lines: an Express app applying
 * the README's recipe, verbatim, in front of `derive`, which is all
 * st-gateway has.
 */
const laneOverTheWire = async (
  stubUrl: string,
  lines: readonly string[]
): Promise<string> => {
  const deriver = createLaneDeriver({ url: stubUrl, secret: SECRET });
  const seen: string[][] = [];
  const app = express();
  app.get("/case", (req, res) => {
    seen.push(authorizationLinesSeen(req));
    void deriver.derive(soleAuthorizationLine(req)).then((lane) => res.json({ lane }));
  });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const { body } = await sendLines(
      (server.address() as AddressInfo).port,
      "GET",
      lines
    );
    expect(seen).toEqual([[...lines]]);
    return body.lane as string;
  } finally {
    server.closeAllConnections();
    server.close();
    await once(server, "close");
  }
};

/** The token a single-value case would send to the center, if any. */
const tokenOf = (testCase: FixtureCase): string | null => {
  const shape = authorizationShape(testCase);
  if (shape.kind === "lines" || shape.value === null) return null;
  return shape.value.toLowerCase().startsWith("bearer ")
    ? shape.value.slice("bearer ".length).trim()
    : null;
};

describe("calling-service cases", () => {
  for (const testCase of fixture.cases) {
    it(`${testCase.name}: ${testCase.why.split(".")[0]}`, async () => {
      await withCase(testCase, async (stub) => {
        const counter = countFetches();
        let decision: Decision;
        let elapsedMs: number;
        try {
          const shape = authorizationShape(testCase);
          const startedAt = Date.now();
          if (shape.kind === "lines") {
            decision = await decideOverTheWire(testCase, stub.url, shape.lines);
          } else {
            const authorizer = createAuthorizer({ url: stub.url, secret: SECRET });
            decision = await authorizer.authorize({
              method: testCase.route?.method ?? "GET",
              requires: testCase.route?.requires ?? "none",
              authorization: shape.value,
            });
          }
          elapsedMs = Date.now() - startedAt;
        } finally {
          counter.restore();
        }

        const expected = testCase.expect;

        if (expected.outcome === "proceed") {
          if (decision.outcome !== "proceed") {
            throw new Error(
              `expected proceed, got ${decision.status} ${decision.message}`
            );
          }
          expect(decision.identity).toEqual(expected.identity);
        } else {
          if (decision.outcome !== "reject") {
            throw new Error(
              `expected reject, got proceed with ${JSON.stringify(decision.identity)}`
            );
          }
          expect(decision.status).toBe(expected.status);
          expect(decision.message).toBe(expected.message);
          for (const forbidden of (expected.messageMustNotContain ??
            []) as string[]) {
            expect(decision.message).not.toContain(forbidden);
          }
        }

        if (expected.maxElapsedMs !== undefined) {
          expect(elapsedMs).toBeLessThanOrEqual(expected.maxElapsedMs as number);
        }

        assertCenterTraffic(testCase, stub, counter.calls, tokenOf(testCase));
      });
    });
  }
});

describe("gateway lane cases", () => {
  for (const testCase of fixture.gatewayCases) {
    it(`${testCase.name}: ${testCase.why.split(".")[0]}`, async () => {
      await withCase(testCase, async (stub) => {
        const counter = countFetches();
        let lane: string;
        try {
          const shape = authorizationShape(testCase);
          lane =
            shape.kind === "lines"
              ? await laneOverTheWire(stub.url, shape.lines)
              : await createLaneDeriver({ url: stub.url, secret: SECRET }).derive(
                  shape.value
                );
        } finally {
          counter.restore();
        }

        // The only verdict this group has. A case that produced a status code
        // would mean the gateway had started rejecting things.
        expect(testCase.expect.outcome).toBe("lane");
        expect(testCase.expect.status).toBeUndefined();
        expect(lane).toBe(testCase.expect.lane);

        assertCenterTraffic(testCase, stub, counter.calls, tokenOf(testCase));
      });
    });
  }
});
