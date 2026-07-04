import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { DEFAULT_SETTINGS } from "../src/settings";
import { afterEach, describe, expect, it } from "vitest";
import {
	DEFAULT_NOTETWEET_DATA,
	parseArgs,
	provisionVault,
	resolveProvisionOptions,
	toShellExports,
} from "./provision-obsidian-e2e-vault.mjs";

const tempRoots: string[] = [];

async function makeTempDir(name: string) {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), `${name}-`));
	tempRoots.push(dir);
	return dir;
}

// NoteTweet ships manifest.json + main.js + a hand-written styles.css, so a
// seeded worktree mirrors all three artifacts that provisioning links.
async function seedWorktree(dir: string, label: string) {
	await fs.mkdir(dir, { recursive: true });
	await fs.writeFile(
		path.join(dir, "manifest.json"),
		JSON.stringify({ id: "notetweet" }),
	);
	await fs.writeFile(
		path.join(dir, "main.js"),
		`console.log(${JSON.stringify(label)});\n`,
	);
	await fs.writeFile(
		path.join(dir, "styles.css"),
		`/* ${label} */\n`,
	);
}

async function readLinkedTarget(filePath: string) {
	return path.resolve(path.dirname(filePath), await fs.readlink(filePath));
}

afterEach(async () => {
	await Promise.all(
		tempRoots
			.splice(0)
			.map((dir) => fs.rm(dir, { recursive: true, force: true })),
	);
});

describe("provision-obsidian-e2e-vault", () => {
	it("parses vault and root options", () => {
		const options = resolveProvisionOptions(
			parseArgs(["--vault", "notetweet-a", "--root", "vaults"]),
			"/tmp/notetweet-repo",
		);

		expect(options.vaultName).toBe("notetweet-a");
		expect(options.rootPath).toBe("/tmp/notetweet-repo/vaults");
		expect(options.vaultPath).toBe("/tmp/notetweet-repo/vaults/notetweet-a");
	});

	it("seeds a data.json that mirrors the real DEFAULT_SETTINGS", () => {
		// Compare the serialized forms — this is exactly what lands in the vault's
		// data.json, and it fails if a setting is added to
		// src/settings.ts without updating DEFAULT_NOTETWEET_DATA.
		expect(JSON.parse(JSON.stringify(DEFAULT_NOTETWEET_DATA))).toEqual(
			JSON.parse(JSON.stringify(DEFAULT_SETTINGS)),
		);
	});

	it("defaults the vault name to notetweet-<worktree>", () => {
		const options = resolveProvisionOptions(
			parseArgs([]),
			"/tmp/repos/devx-worktree-vault-isolation",
		);

		expect(options.vaultName).toBe("notetweet-devx-worktree-vault-isolation");
	});

	it("anchors the default vault root to the worktree, not cwd", () => {
		// --worktree elsewhere without --root must keep the vault inside that
		// checkout (worktree-local isolation), not the caller's cwd.
		const options = resolveProvisionOptions(
			parseArgs(["--worktree", "/tmp/other/checkout"]),
			"/tmp/caller-cwd",
		);

		expect(options.rootPath).toBe("/tmp/other/checkout/.obsidian-e2e-vaults");
		expect(options.vaultPath).toBe(
			"/tmp/other/checkout/.obsidian-e2e-vaults/notetweet-checkout",
		);
	});

	it("creates an Obsidian vault with NoteTweet symlinked from a worktree", async () => {
		const root = await makeTempDir("notetweet-e2e-root");
		const worktree = await makeTempDir("notetweet-worktree-a");
		await seedWorktree(worktree, "a");

		const options = resolveProvisionOptions({
			root,
			vault: "notetweet-a",
			worktree,
		});

		const result = await provisionVault(options);
		const pluginPath = path.join(
			result.vaultPath,
			".obsidian",
			"plugins",
			"notetweet",
		);

		await expect(
			fs.readFile(
				path.join(result.vaultPath, ".obsidian", "community-plugins.json"),
				"utf8",
			),
		).resolves.toBe('[\n\t"notetweet"\n]\n');
		await expect(
			readLinkedTarget(path.join(pluginPath, "main.js")),
		).resolves.toBe(path.join(worktree, "main.js"));
		await expect(
			readLinkedTarget(path.join(pluginPath, "manifest.json")),
		).resolves.toBe(path.join(worktree, "manifest.json"));
		await expect(
			readLinkedTarget(path.join(pluginPath, "styles.css")),
		).resolves.toBe(path.join(worktree, "styles.css"));
		const seededData = JSON.parse(
			await fs.readFile(path.join(pluginPath, "data.json"), "utf8"),
		);
		expect(seededData).toEqual(DEFAULT_NOTETWEET_DATA);
		expect(toShellExports(result)).toContain("NOTETWEET_E2E_VAULT='notetweet-a'");
		expect(toShellExports(result)).toContain(
			`NOTETWEET_E2E_VAULT_PATH='${result.vaultPath}'`,
		);
	});

	it("keeps separately provisioned worktrees isolated", async () => {
		const root = await makeTempDir("notetweet-e2e-root");
		const worktreeA = await makeTempDir("notetweet-worktree-a");
		const worktreeB = await makeTempDir("notetweet-worktree-b");
		await seedWorktree(worktreeA, "a");
		await seedWorktree(worktreeB, "b");

		const resultA = await provisionVault(
			resolveProvisionOptions({
				root,
				vault: "notetweet-a",
				worktree: worktreeA,
			}),
		);
		const resultB = await provisionVault(
			resolveProvisionOptions({
				root,
				vault: "notetweet-b",
				worktree: worktreeB,
			}),
		);

		const mainA = path.join(
			resultA.vaultPath,
			".obsidian",
			"plugins",
			"notetweet",
			"main.js",
		);
		const mainB = path.join(
			resultB.vaultPath,
			".obsidian",
			"plugins",
			"notetweet",
			"main.js",
		);

		await expect(readLinkedTarget(mainA)).resolves.toBe(
			path.join(worktreeA, "main.js"),
		);
		await expect(readLinkedTarget(mainB)).resolves.toBe(
			path.join(worktreeB, "main.js"),
		);
		expect(resultA.vaultPath).not.toBe(resultB.vaultPath);
	});

	it("does not overwrite existing plugin data", async () => {
		const root = await makeTempDir("notetweet-e2e-root");
		const worktree = await makeTempDir("notetweet-worktree");
		const seedData = path.join(await makeTempDir("notetweet-seed"), "data.json");
		await seedWorktree(worktree, "a");
		await fs.writeFile(seedData, '{"UIElements":{"enabled":false}}\n');

		const options = resolveProvisionOptions({
			data: seedData,
			root,
			vault: "notetweet-data",
			worktree,
		});

		const result = await provisionVault(options);
		const dataPath = path.join(result.pluginPath, "data.json");
		// First provision with --data copies the seed verbatim (not DEFAULT_NOTETWEET_DATA).
		await expect(fs.readFile(dataPath, "utf8")).resolves.toBe(
			'{"UIElements":{"enabled":false}}\n',
		);

		await fs.writeFile(dataPath, '{"UIElements":{"enabled":true}}\n');
		await provisionVault(options);

		await expect(fs.readFile(dataPath, "utf8")).resolves.toBe(
			'{"UIElements":{"enabled":true}}\n',
		);
	});

	it("fails fast when the worktree has no built plugin artifacts", async () => {
		const root = await makeTempDir("notetweet-e2e-root");
		const worktree = await makeTempDir("notetweet-worktree-empty");

		await expect(
			provisionVault(
				resolveProvisionOptions({ root, vault: "notetweet-empty", worktree }),
			),
		).rejects.toThrow(/missing manifest\.json, main\.js/);
	});
});
