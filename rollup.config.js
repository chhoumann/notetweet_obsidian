import typescript from "@rollup/plugin-typescript";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import svelte from "rollup-plugin-svelte";
import autoPreprocess from "svelte-preprocess";
import stripCode from "rollup-plugin-strip-code";

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
    process.env["BUILD"] ? stripCode({
      start_comment: 'START.DEVCMD',
      end_comment: 'END.DEVCMD'
    }) : null
  ],
};
