/**
 * @file Loads the vendored fixture, and refuses to let it drift.
 *
 * Three guards, all of which fail loudly rather than skip:
 *
 * - the file's sha256 must equal the one recorded in `SOURCE`, so an edit to
 *   the copy is a red test instead of silent divergence from meta;
 * - the sorted list of case names is asserted in the suite, so a case added
 *   upstream fails here until it is implemented;
 * - an unknown key in `expect` or `center` throws, so a copy that falls behind
 *   says so instead of quietly checking less (meta#79).
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const FIXTURE_PATH = join(__dirname, "..", "fixtures", "introspection.json");
export const SOURCE_PATH = join(__dirname, "..", "fixtures", "SOURCE");

export const fixtureBytes = (): Buffer => readFileSync(FIXTURE_PATH);

export const fixtureSha256 = (): string =>
  createHash("sha256").update(fixtureBytes()).digest("hex");

/** The sha256 the SOURCE record claims. */
export const recordedSha256 = (): string => {
  const text = readFileSync(SOURCE_PATH, "utf8");
  const match = /sha256\s+([0-9a-f]{64})/.exec(text);
  if (match?.[1] === undefined) {
    throw new Error("test/fixtures/SOURCE does not record a sha256");
  }
  return match[1];
};

/** The byte count the SOURCE record claims. */
export const recordedBytes = (): number => {
  const text = readFileSync(SOURCE_PATH, "utf8");
  const match = /bytes\s+(\d+)/.exec(text);
  if (match?.[1] === undefined) {
    throw new Error("test/fixtures/SOURCE does not record a byte count");
  }
  return Number(match[1]);
};

export interface FixtureCase {
  readonly name: string;
  readonly why: string;
  readonly route?: { readonly method: string; readonly requires: string };
  /**
   * Version 4: a string (one `Authorization` line), null (none), or an array
   * of two or more strings, one per header line in the order sent. Read it
   * through {@link authorizationShape}, which refuses anything else.
   */
  readonly request: { readonly authorization: unknown };
  readonly center: Record<string, unknown>;
  readonly expect: Record<string, unknown>;
}

export interface Fixture {
  readonly version: number;
  readonly contract: {
    readonly endpoint: {
      readonly method: string;
      readonly path: string;
      readonly contentType: string;
      readonly bodyTemplate: string;
      readonly secretHeader: string;
    };
    readonly env: { readonly url: string; readonly secret: string };
    readonly clientTimeoutMs: number;
    readonly retries: number;
    readonly messages: Record<string, string>;
  };
  readonly cases: readonly FixtureCase[];
  readonly gatewayCases: readonly FixtureCase[];
}

export const loadFixture = (): Fixture =>
  JSON.parse(fixtureBytes().toString("utf8")) as Fixture;

const KNOWN_EXPECT_KEYS = new Set([
  "outcome",
  "identity",
  "centerCalls",
  "centerRequest",
  "status",
  "message",
  "messageMustNotContain",
  "maxElapsedMs",
  "lane",
]);

/**
 * Every key of `expect` must be one this suite knows how to assert. An
 * unrecognised key is a condition nobody is checking, which is exactly the
 * failure meta#79 recorded.
 */
export const assertKnownExpectKeys = (
  caseName: string,
  expected: Record<string, unknown>
): void => {
  for (const key of Object.keys(expected)) {
    if (!KNOWN_EXPECT_KEYS.has(key)) {
      throw new Error(
        `${caseName}: unknown expect key "${key}" — this suite would silently skip it`
      );
    }
  }
};

/** A case's `request.authorization`, in one of the shapes version 4 allows. */
export type AuthorizationShape =
  | { readonly kind: "value"; readonly value: string | null }
  | { readonly kind: "lines"; readonly lines: readonly string[] };

/**
 * Classify `request.authorization`, and throw on any shape this suite cannot
 * send. An array of fewer than two lines, a non-string line, a number or an
 * object is not something the fixture defines; running it as "no header"
 * would be a case quietly checking less.
 */
export const authorizationShape = (testCase: FixtureCase): AuthorizationShape => {
  const value = testCase.request.authorization;
  if (value === null || typeof value === "string") return { kind: "value", value };
  if (
    Array.isArray(value) &&
    value.length >= 2 &&
    value.every((line) => typeof line === "string")
  ) {
    return { kind: "lines", lines: value };
  }
  throw new Error(
    `${testCase.name}: unknown request.authorization shape ${JSON.stringify(value)} — ` +
      "expected a string, null, or an array of two or more strings"
  );
};

/**
 * Counts every HTTP request the client actually makes, including ones to a
 * port with nothing listening, which no server-side counter can see.
 *
 * `centerCalls: 0` and `centerCalls: 1` are both real assertions, and this is
 * what makes a helpful retry loop fail.
 */
export interface FetchCounter {
  readonly calls: number;
  restore(): void;
}

export const countFetches = (): FetchCounter => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = ((...args: Parameters<typeof fetch>) => {
    calls += 1;
    return original(...args);
  });
  return {
    get calls() {
      return calls;
    },
    restore() {
      globalThis.fetch = original;
    },
  };
};
