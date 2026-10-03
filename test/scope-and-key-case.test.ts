/**
 * @file What separates scopes, and top-level keys that differ only in case
 * (meta fixture version 6, 2.0.1).
 *
 * The fixture pins the cases every client must agree on. This suite pins the
 * rest of each rule as this package applies it: `splitScopes` directly, over
 * every character JavaScript's `\s` matches, and the top-level key check
 * over every contract key, unknown keys, escaped spellings and nested
 * objects, where a case variant is still read.
 */

import { createAuthorizer } from "../src/core";
import { createLaneDeriver } from "../src/gateway";
import { splitScopes } from "../src/center";
import { MESSAGES } from "../src/messages";
import { startStubCenter } from "./support/stubCenter";

const SECRET = "scope-and-key-case-suite-secret";

/** The decision a route requiring `requires` gets when the center answers `body`. */
const decide = async (body: string, requires = "fleet:control", method = "POST") => {
  const center = await startStubCenter({ status: 200, body });
  try {
    const decision = await createAuthorizer({ url: center.url, secret: SECRET }).authorize({
      method,
      requires,
      authorization: "Bearer some.opaque.token",
    });
    return { decision, calls: center.requests.length };
  } finally {
    await center.close();
  }
};

const answer = (members: string) =>
  `{"active":true,"sub":"user_a","exp":4102444800,"kind":"operator",${members}}`;

const UNAVAILABLE = {
  outcome: "reject",
  status: 503,
  message: MESSAGES.centerUnavailable,
} as const;

describe("splitScopes", () => {
  it("splits on runs of space, tab, CR and LF and discards the empties", () => {
    expect(splitScopes("a b")).toEqual(["a", "b"]);
    expect(splitScopes("a\tb")).toEqual(["a", "b"]);
    expect(splitScopes("a\rb")).toEqual(["a", "b"]);
    expect(splitScopes("a\nb")).toEqual(["a", "b"]);
    expect(splitScopes(" \t\r\n a \t\r\n b \t\r\n ")).toEqual(["a", "b"]);
    expect(splitScopes("")).toEqual([]);
    expect(splitScopes(" \t\r\n ")).toEqual([]);
  });

  // Every character JavaScript's \s matches other than the four separators,
  // plus U+0085 and U+180E, which it does not: each is part of the token.
  const notSeparators: Array<[string, string]> = [
    ["VT", "\u000b"],
    ["FF", "\u000c"],
    ["NEXT LINE", "\u0085"],
    ["NO-BREAK SPACE", " "],
    ["OGHAM SPACE MARK", " "],
    ["MONGOLIAN VOWEL SEPARATOR", "᠎"],
    ...Array.from({ length: 11 }, (_, i): [string, string] => [
      `U+${(0x2000 + i).toString(16).toUpperCase()}`,
      String.fromCharCode(0x2000 + i),
    ]),
    ["LINE SEPARATOR", " "],
    ["PARAGRAPH SEPARATOR", " "],
    ["NARROW NO-BREAK SPACE", " "],
    ["MEDIUM MATHEMATICAL SPACE", " "],
    ["IDEOGRAPHIC SPACE", "　"],
    ["ZERO WIDTH NO-BREAK SPACE", "﻿"],
  ];

  it.each(notSeparators)("keeps %s inside the token", (_name, c) => {
    expect(splitScopes(`fleet:control${c}agent:reset`)).toEqual([`fleet:control${c}agent:reset`]);
    expect(splitScopes(`${c}fleet:control${c}`)).toEqual([`${c}fleet:control${c}`]);
    expect(splitScopes(`a${c}b c`)).toEqual([`a${c}b`, "c"]);
  });
});

describe("a scope joined by a non-separator is one scope, through the authorizer", () => {
  it.each([
    ["NO-BREAK SPACE", "\\u00a0"],
    ["EM SPACE", "\\u2003"],
    ["VT", "\\u000b"],
    ["FF", "\\f"],
  ])("%s: neither half is granted", async (_name, escape) => {
    for (const requires of ["fleet:control", "agent:reset"]) {
      const { decision, calls } = await decide(
        answer(`"scope":"fleet:control${escape}agent:reset"`),
        requires
      );
      expect(decision).toEqual({
        outcome: "reject",
        status: 403,
        message: MESSAGES.missingScope,
      });
      expect(calls).toBe(1);
    }
  });

  it("a tab still separates them", async () => {
    const { decision } = await decide(answer('"scope":"fleet:control\\tagent:reset"'), "agent:reset");
    expect(decision).toEqual({
      outcome: "proceed",
      identity: { sub: "user_a", kind: "operator", scopes: ["fleet:control", "agent:reset"] },
    });
  });
});

describe("top-level keys equal ignoring case are a malformed answer", () => {
  const refused: Array<[string, string]> = [
    ["Active after active", answer('"scope":"fleet:control","Active":false')],
    ["ACTIVE before active", '{"ACTIVE":false,"active":true,"sub":"user_a","scope":"fleet:control","exp":4102444800,"kind":"operator"}'],
    ["Sub beside sub", answer('"scope":"fleet:control","Sub":"user_b"')],
    ["SCOPE beside scope", answer('"scope":"fleet:control","SCOPE":""')],
    ["Exp beside exp", answer('"scope":"fleet:control","Exp":1')],
    ["kInD beside kind", answer('"scope":"fleet:control","kInD":"machine"')],
    ["an unknown key in two spellings", answer('"scope":"fleet:control","ext":1,"EXT":1')],
    ["an escaped capital", answer('"scope":"fleet:control","\\u0053ub":"user_b"')],
    // Lowered by toLowerCase(), as Java and Go lower it: KELVIN SIGN is k.
    ["KELVIN SIGN spelling of kind", answer('"scope":"fleet:control","\\u212Aind":"machine"')],
    ["a miscased contract key alone: Scope", answer('"Scope":"fleet:control"')],
    ["a miscased contract key alone: EXP", '{"active":true,"sub":"user_a","scope":"fleet:control","EXP":4102444800,"kind":"operator"}'],
    ["a miscased active, even inactive", '{"Active":false}'],
    ["a miscased sub on an inactive answer", '{"active":false,"Sub":"user_a"}'],
  ];

  it.each(refused)("%s is 503 after one call", async (_name, body) => {
    const { decision, calls } = await decide(body);
    expect(decision).toEqual(UNAVAILABLE);
    expect(calls).toBe(1);
  });

  it("lanes background at the gateway, never interactive", async () => {
    const center = await startStubCenter({
      status: 200,
      body: answer('"scope":"fleet:control","Kind":"machine"'),
    });
    try {
      const lane = await createLaneDeriver({ url: center.url, secret: SECRET }).derive(
        "Bearer some.opaque.token"
      );
      expect(lane).toBe("background");
      expect(center.requests).toHaveLength(1);
    } finally {
      await center.close();
    }
  });
});

describe("what is not a case variant is still read", () => {
  it.each([
    ["a case variant below the top level", answer('"scope":"fleet:control","x":{"k":1,"K":2}')],
    ["an unknown key that merely contains a contract key", answer('"scope":"fleet:control","Subject":"x","kinds":1')],
    ["an unknown capitalised key", answer('"scope":"fleet:control","Ext":1')],
    // Long s is already lower case, so no lowering folds it onto `s`.
    ["LONG S spelling of sub", answer('"scope":"fleet:control","\\u017Fub":"user_b"')],
  ])("%s proceeds", async (_name, body) => {
    const { decision, calls } = await decide(body);
    expect(decision).toEqual({
      outcome: "proceed",
      identity: { sub: "user_a", kind: "operator", scopes: ["fleet:control"] },
    });
    expect(calls).toBe(1);
  });

  it("an inactive answer with only exact keys is still a 401", async () => {
    const { decision } = await decide('{"active":false,"ext":{"Active":true}}');
    expect(decision).toEqual({ outcome: "reject", status: 401, message: MESSAGES.invalidSession });
  });
});
