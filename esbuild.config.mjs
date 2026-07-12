import esbuild from "esbuild";
import { createBuildOptions } from "./esbuild.options.mjs";

const isProduction = process.argv.includes("production");
const options = createBuildOptions({ production: isProduction });

if (isProduction) {
  await esbuild.build(options);
} else {
  const context = await esbuild.context(options);
  await context.watch();
}
