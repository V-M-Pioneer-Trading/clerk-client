/** @type {import("ts-jest").JestConfigWithTSJest} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["<rootDir>/test/**/*.test.ts"],
  // heinzelwerk task worktrees are full checkouts of this repo: their copies
  // of the tests belong to their own run.
  modulePathIgnorePatterns: ["<rootDir>/.claude/worktrees/"],
  // The conformance suite drives a real HTTP stub, including a 3 s delay
  // against a 1 s client timeout.
  testTimeout: 15000,
  // A stub center or a socket left open is a defect in the test, not
  // something to paper over with --forceExit.
  detectOpenHandles: true,
};
