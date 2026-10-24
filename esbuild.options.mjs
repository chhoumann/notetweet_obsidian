import { builtinModules } from "node:module";

// twitter-text declares the browser-safe punycode package it imports. Do not
// externalize that bare specifier as Node's deprecated builtin: mobile Obsidian
// has no Node runtime, so esbuild must resolve and inline the package instead.
const browserBundledModules = new Set(["punycode"]);
const externalBuiltins = builtinModules.filter(
  (module) => !browserBundledModules.has(module),
);

// twitter-text's ESM build imports core-js 2 polyfills (side-effect imports
// only) for ES2015 builtins every supported Obsidian runtime has natively.
// Bundling them would patch globals shared with Obsidian and other plugins.
const stripCoreJsPolyfills = {
  name: "strip-core-js-polyfills",
  setup(build) {
    build.onResolve({ filter: /^core-js\/modules\// }, (args) => ({
      path: args.path,
      namespace: "stripped-polyfill",
    }));
    build.onLoad({ filter: /.*/, namespace: "stripped-polyfill" }, () => ({
      contents: "",
    }));
  },
};

export function createBuildOptions({ production = false } = {}) {
  return {
    entryPoints: ["src/main.ts"],
    bundle: true,
    outfile: "main.js",
    format: "cjs",
    platform: "browser",
    target: "es2020",
    sourcemap: production ? false : "inline",
    treeShaking: true,
    external: [
      "obsidian",
      "electron",
      "@codemirror/*",
      "@lezer/*",
      ...externalBuiltins,
      ...externalBuiltins.map((module) => `node:${module}`),
    ],
    logLevel: "info",
    define: {
      "process.env.NODE_ENV": JSON.stringify(
        production ? "production" : "development",
      ),
    },
    plugins: [stripCoreJsPolyfills],
  };
}
