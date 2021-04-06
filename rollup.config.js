import typescript from "@rollup/plugin-typescript";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import svelte from "rollup-plugin-svelte";
import autoPreprocess from "svelte-preprocess";
import copy from "rollup-plugin-copy";

const path = ".";
export default {
  input: "src/main.ts",
  output: {
    dir: path,
    format: "cjs",
    exports: "default",
  },
  external: ["obsidian"],
  plugins: [
    svelte({
      emitCss: false,
      preprocess: autoPreprocess(),
    }),
    typescript(),
    resolve({ browser: true, dedupe: ["svelte"] }),
    commonjs({ include: "node_modules/**" }),
    copy({
      targets: [
        {
          src: "manifest.json",
          dest: path,
        },
        {
          src: "styles.css",
          dest: path,
        },
      ],
    }),
  ],
};
