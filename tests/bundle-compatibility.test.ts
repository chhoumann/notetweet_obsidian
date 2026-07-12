import { builtinModules } from "node:module";
import esbuild from "esbuild";
import { describe, expect, it } from "vitest";
import { createBuildOptions } from "../esbuild.options.mjs";

describe("production bundle compatibility", () => {
	it("bundles twitter-text's browser punycode implementation", async () => {
		const result = await esbuild.build({
			...createBuildOptions({ production: true }),
			metafile: true,
			write: false,
			logLevel: "silent",
		});
		const bundle = result.outputFiles.find((file) => file.path.endsWith("main.js"));
		expect(bundle).toBeDefined();

		const code = bundle?.text ?? "";
		const requires = [...code.matchAll(/\brequire\(["']([^"']+)["']\)/g)].map(
			(match) => match[1],
		);
		const nodeBuiltins = new Set([
			...builtinModules,
			...builtinModules.map((module) => `node:${module}`),
		]);

		expect(requires).not.toContain("punycode");
		expect(requires.filter((specifier) => nodeBuiltins.has(specifier))).toEqual([]);
		expect(
			Object.keys(result.metafile.inputs).some((path) =>
				path.includes("/punycode@1.4.1/node_modules/punycode/punycode.js"),
			),
		).toBe(true);
	});
});
