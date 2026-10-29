import { base } from "@v-m-pioneer-trading/eslint-config";

export default base({
  tsconfigRootDir: import.meta.dirname,
  // Written by scripts/check-readme.mjs (gitignored, regenerated every run).
  // .claude/worktrees/ holds agent task worktrees: full checkouts of this repo, linted in their own run.
  ignores: [".readme-check/", ".claude/worktrees/"],
});
