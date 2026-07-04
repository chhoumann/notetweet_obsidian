import { builtinModules } from "node:module";
import esbuild from "esbuild";

const isProduction = process.argv.includes("production");

const external = [
  "obsidian",
  "electron",
  "@codemirror/*",
  "@lezer/*",
  ...builtinModules,
  ...builtinModules.map((m) => `node:${m}`),
];

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
  plugins: [],
};

if (isProduction) {
  await esbuild.build(options);
} else {
  const context = await esbuild.context(options);
  await context.watch();
}
