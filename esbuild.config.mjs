import { builtinModules } from "node:module";
import { readFile } from "node:fs/promises";
import { dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import esbuild from "esbuild";

const isProduction = process.argv.includes("production");
const projectSrcDir = `${join(dirname(fileURLToPath(import.meta.url)), "src")}${sep}`;
const devCommandBlockPattern = /\/\*\s*START\.DEVCMD\s*\*\/[\s\S]*?\/\*\s*END\.DEVCMD\s*\*\//g;

const external = [
  "obsidian",
  "electron",
  "@codemirror/*",
  "@lezer/*",
  ...builtinModules,
  ...builtinModules.map((m) => `node:${m}`),
];

function stripDevCommandBlocks() {
  return {
    name: "strip-dev-command-blocks",
    setup(build) {
      build.onLoad({ filter: /\.[cm]?[jt]sx?$/ }, async (args) => {
        if (!args.path.startsWith(projectSrcDir)) return null;
        const contents = await readFile(args.path, "utf8");
        if (!contents.includes("DEVCMD")) return null;
        const stripped = contents.replace(devCommandBlockPattern, "");
        if (stripped.includes("DEVCMD")) {
          throw new Error(`Unmatched START.DEVCMD/END.DEVCMD block in ${args.path}`);
        }
        return { contents: stripped, loader: "ts" };
      });
    },
  };
}

const options = {
  entryPoints: ["src/main.ts"],
  bundle: true,
  outfile: "main.js",
  format: "cjs",
  platform: "browser",
  target: "es2020",
  sourcemap: isProduction ? false : "inline",
  treeShaking: true,
  external,
  logLevel: "info",
  define: {
    "process.env.NODE_ENV": JSON.stringify(isProduction ? "production" : "development"),
  },
  plugins: [...(isProduction ? [stripDevCommandBlocks()] : [])],
};

if (isProduction) {
  await esbuild.build(options);
} else {
  const context = await esbuild.context(options);
  await context.watch();
}
