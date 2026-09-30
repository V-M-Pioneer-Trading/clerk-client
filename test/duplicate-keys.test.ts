/**
 * @file A key named twice in a center answer is a malformed answer.
 *
 * The fixture (version 5) pins one top-level repeat of `sub`. This suite pins
 * the rest of the rule this package applies, which is Jackson's: an exact
 * repeat in ANY object, at ANY depth, compared after escapes are decoded, is
 * 503 — and the same key in two different objects is not a repeat. It also
 * pins that the strict reader accepts and builds exactly what `JSON.parse`
 * does for everything else, so the fix cannot quietly refuse a body that used
 * to be read.
 */

import express from "express";
import request from "supertest";

import { createIntrospector } from "../src/center";
import { createAuthorizer } from "../src/core";
import { createExpressAuth, identityOf, secured } from "../src/express";
import { createLaneDeriver } from "../src/gateway";
import { DEFAULT_MAX_RESPONSE_BYTES, MESSAGES } from "../src/messages";
import { parseStrictJson } from "../src/strictJson";
import { loadFixture } from "./support/fixture";
import { startStubCenter, type CenterSpec } from "./support/stubCenter";

const SECRET = "duplicate-keys-suite-secret";
const TOKEN = "duplicate.token.one";

const UNAVAILABLE = {
  outcome: "reject",
  status: 503,
  message: MESSAGES.centerUnavailable,
} as const;

/** The decision a scoped POST gets when the center answers `body`. */
const decide = async (body: string, requires = "fleet:control") => {
  const center = await startStubCenter({ status: 200, body });
  try {
    const decision = await createAuthorizer({ url: center.url, secret: SECRET }).authorize({
      method: "POST",
      requires,
      authorization: `Bearer ${TOKEN}`,
    });
    return { decision, calls: center.requests.length };
  } finally {
    await center.close();
  }
};

const ANSWER = (extra = "") =>
  `{"active":true,"sub":"user_a","scope":"fleet:control","exp":4102444800,"kind":"operator"${extra}}`;

describe("the fixture's duplicate-key cases, through the adapter consumers use", () => {
  const fixture = loadFixture();
  const calling = fixture.cases.find((c) => c.name === "center-returns-duplicate-key");
  const gateway = fixture.gatewayCases.find(
    (c) => c.name === "gateway-center-returns-duplicate-key"
  );

  it("are in the vendored fixture", () => {
    expect(calling).toBeDefined();
    expect(gateway).toBeDefined();
  });

  it("center-returns-duplicate-key is 503 through real Express and createExpressAuth", async () => {
    if (calling === undefined) throw new Error("case missing");
    const center = await startStubCenter(calling.center as CenterSpec);
    try {
      const auth = createExpressAuth({ url: center.url, secret: SECRET });
      const api = secured(express.Router());
      api.post("/case", auth.requireScope(calling.route?.requires ?? ""), (_req, res) => {
        res.json({ identity: identityOf(res) });
      });
      const app = express();
      app.use(api);
      const response = await request(app)
        .post("/case")
        .set("Authorization", calling.request.authorization as string);
      expect(response.status).toBe(calling.expect.status);
      expect(response.body).toEqual({ error: { message: calling.expect.message } });
      expect(center.requests).toHaveLength(calling.expect.centerCalls as number);
    } finally {
      await center.close();
    }
  });

  it("gateway-center-returns-duplicate-key lanes background through createLaneDeriver", async () => {
    if (gateway === undefined) throw new Error("case missing");
    const center = await startStubCenter(gateway.center as CenterSpec);
    try {
      const lane = await createLaneDeriver({ url: center.url, secret: SECRET }).derive(
        gateway.request.authorization as string
      );
      expect(lane).toBe(gateway.expect.lane);
      expect(center.requests).toHaveLength(gateway.expect.centerCalls as number);
    } finally {
      await center.close();
    }
  });
});

describe("a repeated key anywhere in the answer is 503, after one call", () => {
  const repeated: Array<[string, string]> = [
    ["a repeat at depth", '{"active":true,"sub":"a","x":{"k":1,"k":2}}'],
    // The line above would be 503 without the rule too (no exp, no kind). These
    // are otherwise-valid answers, so only the duplicate check refuses them.
    ["a repeat at depth, in a full answer", ANSWER(',"x":{"k":1,"k":2}')],
    [
      "a repeat at depth inside an array, in a full answer",
      ANSWER(',"ext":[{"deep":{"k":1,"k":1}}]'),
    ],
    ["sub and its unicode-escaped spelling", ANSWER(',"s\\u0075b":"user_b"')],
    ["an escaped spelling at depth", ANSWER(',"x":{"k\\u0031":1,"k1":2}')],
    [
      "active twice with different values",
      '{"active":false,"sub":"user_a","scope":"fleet:control","exp":4102444800,"kind":"operator","active":true}',
    ],
    ["active twice with the same value", ANSWER(',"active":true')],
    ["kind twice", ANSWER(',"kind":"machine"')],
    ["an unknown key twice", ANSWER(',"ext":1,"ext":1')],
    ["__proto__ twice", ANSWER(',"__proto__":{},"__proto__":{}')],
  ];

  it.each(repeated)("%s", async (_label, body) => {
    const { decision, calls } = await decide(body);
    expect(decision).toEqual(UNAVAILABLE);
    expect(calls).toBe(1);
  });

  it("lanes background at the gateway, never interactive", async () => {
    const center = await startStubCenter({
      status: 200,
      body: ANSWER(',"x":{"k":1,"k":2}'),
    });
    try {
      const lane = await createLaneDeriver({ url: center.url, secret: SECRET }).derive(
        `Bearer ${TOKEN}`
      );
      expect(lane).toBe("background");
    } finally {
      await center.close();
    }
  });
});

describe("what is not a repeat is still read", () => {
  it("the same key in different objects", async () => {
    const { decision } = await decide(
      ANSWER(',"x":{"sub":"user_b","k":1},"y":[{"k":1},{"k":2}],"z":{"x":{"k":3}}')
    );
    expect(decision).toEqual({
      outcome: "proceed",
      identity: { sub: "user_a", kind: "operator", scopes: ["fleet:control"] },
    });
  });

  it("a single __proto__ key, which becomes an own key and no prototype", async () => {
    const { decision } = await decide(ANSWER(',"__proto__":{"polluted":true}'));
    expect(decision.outcome).toBe("proceed");
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("whitespace, an absent scope and a unicode-escaped sub", async () => {
    const { decision } = await decide(
      ' \r\n\t{ "active" : true ,\n "sub":"user_\\u00e9\\ud83d\\ude80" , "exp":4102444800e0,"kind":"operator","ext":null }\n',
      "session"
    );
    expect(decision).toEqual({
      outcome: "proceed",
      identity: { sub: "user_\u00e9\u{1f680}", kind: "operator", scopes: [] },
    });
  });
});

describe("the cap still comes first", () => {
  /** An answer padded with distinct keys to exactly `bytes` bytes. */
  const padded = (bytes: number): string => {
    const head = '{"active":true,"sub":"user_a","scope":"fleet:control","exp":4102444800,"kind":"operator"';
    let body = head;
    for (let i = 0; body.length < bytes - 40; i += 1) body += `,"k${i}":${i}`;
    body += ',"pad":"';
    return body + "x".repeat(bytes - body.length - 2) + '"}';
  };

  it("a 64 KiB answer made of distinct keys is read", async () => {
    const body = padded(DEFAULT_MAX_RESPONSE_BYTES);
    expect(Buffer.byteLength(body)).toBe(DEFAULT_MAX_RESPONSE_BYTES);
    expect(() => JSON.parse(body)).not.toThrow();
    const { decision } = await decide(body);
    expect(decision.outcome).toBe("proceed");
  });

  it("one byte more is 503, as it was before", async () => {
    const { decision } = await decide(padded(DEFAULT_MAX_RESPONSE_BYTES + 1));
    expect(decision).toEqual(UNAVAILABLE);
  });

  it("a repeat past the cap never reaches the parser, and is 503 either way", async () => {
    const center = await startStubCenter({
      status: 200,
      body: ANSWER(`,"pad":"${"x".repeat(200)}","sub":"user_b"`),
    });
    try {
      const answer = await createIntrospector({
        url: center.url,
        secret: SECRET,
        maxResponseBytes: 128,
      }).introspect(TOKEN);
      expect(answer).toEqual({ state: "unavailable" });
    } finally {
      await center.close();
    }
  });
});

describe("invalid JSON is still 503", () => {
  const invalid = [
    "{",
    '{"active":true,}',
    '{"active":true',
    "{'active':true}",
    '{"active":true} x',
    '{"active":true}{}',
    '{"active":tru}',
    '{"active":01}',
    '{"active":true,"sub":"a\nb"}',
    '{"active":true,"sub":"\\x"}',
    '{"active":true,"sub":"\\u12"}',
    "\u00a0{}",
    "not json",
  ];
  it.each(invalid)("%j", async (body) => {
    const { decision } = await decide(body);
    expect(decision).toEqual(UNAVAILABLE);
  });
});

describe("parseStrictJson is JSON.parse, less the repeated key", () => {
  const valid = [
    "0",
    "-0",
    "1.5e+10",
    "-12.25E-3",
    "1e400",
    '"a\\"b\\\\c\\/d\\b\\f\\n\\r\\t"',
    '"\\ud800"',
    '"\\uD83D\\uDE80 \u00e9 🚀"',
    "true",
    "false",
    "null",
    "[]",
    " [ 1 , [ 2 , { } ] , \"x\" ] ",
    '{"a":{"b":[{"c":null}]},"d":-1}',
    '{"":1,"a":{"":2}}',
    '{"__proto__":{"x":1},"constructor":2,"toString":3}',
    ANSWER(),
  ];
  it.each(valid)("reads %j as JSON.parse does", (text) => {
    const strict = parseStrictJson(text);
    expect(strict).toEqual(JSON.parse(text));
    expect(JSON.stringify(strict)).toBe(JSON.stringify(JSON.parse(text)));
  });

  it("keeps __proto__ an own key, as JSON.parse does", () => {
    const parsed = parseStrictJson('{"__proto__":{"x":1}}') as Record<string, unknown>;
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
    expect(Object.keys(parsed)).toEqual(["__proto__"]);
    expect((parsed as { x?: unknown }).x).toBeUndefined();
  });

  const refusedByBoth = [
    "",
    " ",
    "{",
    "[1,]",
    "[,1]",
    '{"a"}',
    '{"a":}',
    '{a:1}',
    '{"a":1,}',
    "01",
    "-",
    "1.",
    ".5",
    "1e",
    "+1",
    "0x1",
    "NaN",
    "Infinity",
    "True",
    "nul",
    "truex",
    '"a',
    '"\\u00g0"',
    '"\\a"',
    '"\t"',
    "// c\n1",
    "\ufeff1",
    "1 2",
  ];
  it.each(refusedByBoth)("refuses %j, as JSON.parse does", (text) => {
    expect(() => JSON.parse(text)).toThrow(SyntaxError);
    expect(() => parseStrictJson(text)).toThrow(SyntaxError);
  });

  it("refuses a repeat that JSON.parse accepts", () => {
    for (const text of ['{"a":1,"a":1}', '[{"a":{"b":1,"b":2}}]', '{"a":1,"\\u0061":2}']) {
      expect(() => JSON.parse(text)).not.toThrow();
      expect(() => parseStrictJson(text)).toThrow(/duplicate key/);
    }
  });

  it("refuses nesting past 1000 levels rather than exhausting the stack", () => {
    const nest = (n: number) => "[".repeat(n) + "]".repeat(n);
    expect(parseStrictJson(nest(1000))).toEqual(JSON.parse(nest(1000)));
    expect(() => parseStrictJson(nest(1001))).toThrow(/nested too deeply/);
    expect(() => parseStrictJson('{"a":'.repeat(20_000))).toThrow(SyntaxError);
  });

  it("parses a normal answer in well under a millisecond", () => {
    const body = ANSWER();
    for (let i = 0; i < 1000; i += 1) parseStrictJson(body); // warm up
    const runs = 10_000;
    const startedAt = process.hrtime.bigint();
    for (let i = 0; i < runs; i += 1) parseStrictJson(body);
    const perParseMs = Number(process.hrtime.bigint() - startedAt) / 1e6 / runs;
    // Typically a few microseconds; a tenth of a millisecond is two orders of
    // magnitude of headroom for a slow CI box.
    expect(perParseMs).toBeLessThan(0.1);
  });
});
