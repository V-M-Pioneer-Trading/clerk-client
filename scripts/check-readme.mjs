/**
 * @file Compile and RUN every fenced TypeScript/JavaScript snippet in README.md.
 *
 * The README is the migration instructions for three services, and its
 * snippets are the spelling those services are told to copy. A snippet that no
 * longer compiles — or that compiles and is then REFUSED at registration by
 * `secured()` — is a defect of the same size as a broken export, and it used
 * to be invisible: the fourth review found `README.md` telling fleet-service
 * to write a construct this package throws on at boot.
 *
 * So each snippet is extracted, given the free identifiers it names (`auth`,
 * `RegisterRoutes`, `swaggerUi`, …) from a shared prelude, typechecked with
 * the repository's own strictness, and then EXECUTED. Executing is the half
 * that matters here: `secured()` enforces at registration time, so running the
 * migration snippet is exactly the boot the consumer would do.
 *
 * Two deliberate transforms, and no others:
 *
 *  1. the package's own name is rewritten to a relative import of `src/`, so
 *     the snippets are checked against this working tree rather than against
 *     whatever is installed;
 *  2. a snippet's leading `import` statements are hoisted above the wrapper
 *     function the rest of its body goes into, which is what lets a snippet
 *     use top-level `await`.
 *
 * Run: `npm run check:readme`.
 */

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const workDir = join(root, ".readme-check");

const PACKAGE_NAME = "@v-m-pioneer-trading/introspection-client";

/** Languages whose fences are claims about this package's API. */
const CHECKED = new Set(["ts", "typescript", "js", "javascript"]);

/** Every fenced block in the README, with the line it starts on. */
const extract = (markdown) => {
  const lines = markdown.split(/\r?\n/);
  const blocks = [];
  let current = null;
  lines.forEach((line, index) => {
    const fence = /^```(\w*)\s*$/.exec(line);
    if (fence === null) {
      if (current !== null) current.body.push(line);
      return;
    }
    if (current === null) {
      current = { lang: fence[1].toLowerCase(), startLine: index + 1, body: [] };
    } else {
      blocks.push({ ...current, body: current.body.join("\n") });
      current = null;
    }
  });
  if (current !== null) {
    throw new Error(`README.md has an unterminated fence at line ${current.startLine}`);
  }
  return blocks;
};

/**
 * Split a snippet into its leading import statements and the rest.
 *
 * An `import` may span lines, so the run ends at the first line that closes
 * one — a line ending in `;` or in `"` — and the scan stops at the first line
 * that does not begin a new import.
 */
const splitImports = (body) => {
  const lines = body.split("\n");
  const imports = [];
  let index = 0;
  while (index < lines.length) {
    if (!/^\s*import\s/.test(lines[index])) break;
    while (index < lines.length) {
      const line = lines[index];
      imports.push(line);
      index += 1;
      if (/;\s*$/.test(line) || /^import\s+["'][^"']+["']\s*$/.test(line)) break;
    }
  }
  return { imports: imports.join("\n"), rest: lines.slice(index).join("\n") };
};

/** The names a snippet imports for itself, which the prelude must not shadow. */
const importedNames = (imports) => {
  const names = new Set();
  for (const match of imports.matchAll(/^\s*import\s+([\s\S]*?)\s+from\s/gm)) {
    const clause = match[1];
    const braced = /\{([\s\S]*)\}/.exec(clause);
    if (braced !== null) {
      for (const part of braced[1].split(",")) {
        const name = part.trim().replace(/^type\s+/, "").split(/\s+as\s+/).pop();
        if (name) names.add(name.trim());
      }
    }
    const bare = clause.replace(/\{[\s\S]*\}/, "").replace(/,/g, "").trim();
    if (bare && !bare.startsWith("*")) names.add(bare);
  }
  return names;
};

const PRELUDE_NAMES = [
  "express",
  "cors",
  "corsOptions",
  "swaggerUi",
  "spec",
  "assetDir",
  "proxy",
  "health",
  "listTargets",
  "navigate",
  "listShips",
  "RegisterRoutes",
  "auth",
  "config",
  "req",
  "actorOf",
  "authorizationLines",
  "identityOf",
  "kindOf",
  "hasScope",
  "requirementOf",
  "createAuthorizer",
  "createExpressAuth",
  "createLaneDeriver",
  "loadIntrospectionConfig",
  "notFound",
  "passthrough",
  "secured",
];

const main = () => {
  const markdown = readFileSync(join(root, "README.md"), "utf8");
  const blocks = extract(markdown).filter((block) => CHECKED.has(block.lang));
  if (blocks.length === 0) {
    throw new Error("README.md has no ts/js snippets — the extractor is broken");
  }

  rmSync(workDir, { recursive: true, force: true });
  mkdirSync(workDir, { recursive: true });
  copyFileSync(join(here, "readme-prelude.ts"), join(workDir, "prelude.ts"));

  const generated = [];
  blocks.forEach((block, index) => {
    const { imports, rest } = splitImports(block.body);
    const mine = importedNames(imports);
    const bound = PRELUDE_NAMES.filter((name) => !mine.has(name));
    const file = `snippet-${String(index + 1).padStart(2, "0")}.ts`;
    generated.push({ file, block });
    writeFileSync(
      join(workDir, file),
      [
        `// GENERATED from README.md lines ${block.startLine}-${
          block.startLine + block.body.split("\n").length + 1
        }.`,
        "// Edit the README, not this file. `npm run check:readme` rewrites it.",
        "/* eslint-disable */",
        imports.replaceAll(`"${PACKAGE_NAME}"`, '"../src/index"'),
        `import { prelude } from "./prelude";`,
        "",
        bound.length > 0
          ? `const { ${bound.join(", ")} } = prelude();`
          : "prelude();",
        "",
        "export async function snippet(): Promise<void> {",
        rest.replaceAll(`"${PACKAGE_NAME}"`, '"../src/index"'),
        "}",
        "",
      ].join("\n"),
      "utf8"
    );
  });

  writeFileSync(
    join(workDir, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          target: "ES2022",
          module: "commonjs",
          moduleResolution: "node",
          esModuleInterop: true,
          strict: true,
          skipLibCheck: true,
          noUnusedLocals: false,
          noUnusedParameters: false,
          rootDir: "..",
          outDir: "dist",
          types: ["node"],
        },
        include: ["*.ts"],
      },
      null,
      2
    ),
    "utf8"
  );

  console.log(`README.md: ${blocks.length} snippet(s) to compile and run`);
  // The compiler is invoked as a JS file under this same `node`, not through
  // `npx`: a `.cmd` shim cannot be spawned without a shell on Windows, and
  // going through a shell would put the paths below through a second parser.
  execFileSync(
    process.execPath,
    [join(root, "node_modules", "typescript", "bin", "tsc"), "-p", join(workDir, "tsconfig.json")],
    { stdio: "inherit", cwd: root }
  );

  return generated;
};

const run = async (generated) => {
  // The env the snippets' `loadIntrospectionConfig()` reads. A URL nothing is
  // listening on: no snippet here is supposed to reach a center, and if one
  // ever does the failure must be a refusal rather than a silent success.
  process.env.AUTH_INTROSPECTION_URL = "http://127.0.0.1:59999/auth/v1/introspect";
  process.env.AUTH_INTROSPECTION_SECRET = "readme-check-secret";

  for (const { file, block } of generated) {
    // rootDir is the repository root — the snippets import `../src` — so tsc
    // mirrors the tree under dist/ and each snippet lands under its own
    // directory name rather than at the top of it.
    const compiled = join(
      workDir,
      "dist",
      ".readme-check",
      file.replace(/\.ts$/, ".js")
    );
    const where = `README.md line ${block.startLine}`;
    try {
      const module = await import(pathToFileURL(compiled).href);
      await module.snippet();
      console.log(`  ok   ${where}`);
    } catch (error) {
      console.error(`  FAIL ${where}\n`);
      console.error(block.body);
      console.error("");
      throw error;
    }
  }
};

const generated = main();
await run(generated);
console.log("every README snippet compiles and runs");
