import { readlink } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
	acquireVaultRunLock,
	captureFailureArtifacts,
	clearVaultRunLockMarker,
	createObsidianClient,
	createSandboxApi,
	type ObsidianClient,
	type PluginHandle,
	type PluginReloadOptions,
	type SandboxApi,
	type VaultRunLock,
	resolveObsidianEnvOptions,
	verifyVaultPath,
} from "obsidian-e2e";
import { afterAll, afterEach, beforeAll, beforeEach } from "vitest";

export const PLUGIN_ID = "notetweet";
// Reads the OBSIDIAN_E2E_* env that `start:e2e-obsidian --print-env` emits and
// binds the CLI to that instance's private HOME.
const { expectedVaultPath, ...obsidianEnv } = resolveObsidianEnvOptions();
// styles.css is a hand-written release asset shipped alongside main.js, so the
// provisioned vault symlinks all three artifacts.
export const PLUGIN_ARTIFACTS = ["main.js", "manifest.json", "styles.css"];
export const WAIT_OPTS = { timeoutMs: 15_000, intervalMs: 200 };
export const RELOAD_OPTIONS: PluginReloadOptions = {
	waitUntilReady: true,
	timeoutMs: 30_000,
	readyOptions: {
		// Plugin-ready sentinel: the "Post tweet" command NoteTweet always
		// registers in onload(). The dev-only "Reload (dev)" command is stripped
		// from production bundles (START.DEVCMD/END.DEVCMD), so it must not be used.
		commandId: `${PLUGIN_ID}:post-tweet`,
		...WAIT_OPTS,
	},
};

type HarnessState = {
	lock?: VaultRunLock;
	obsidian?: ObsidianClient;
	plugin?: PluginHandle;
	sandbox?: SandboxApi;
};

export type NoteTweetE2EContext = {
	obsidian: ObsidianClient;
	plugin: PluginHandle;
	sandbox: SandboxApi;
};

const repoRoot = path.resolve(
	path.dirname(fileURLToPath(import.meta.url)),
	"..",
	"..",
);

export function createNoteTweetE2EHarness(testName: string) {
	const state: HarnessState = {};

	beforeAll(async () => {
		state.obsidian = createObsidianClient({
			...obsidianEnv,
			timeoutMs: 20_000,
			intervalMs: 200,
		});
		await state.obsidian.verify();
		const vaultPath = verifyVaultPath({
			actualVaultPath: await state.obsidian.vaultPath(),
			expectedVaultPath,
			vaultName: obsidianEnv.vault,
		});

		state.lock = await acquireVaultRunLock({
			vaultName: obsidianEnv.vault,
			vaultPath,
			onBusy: "wait",
			timeoutMs: 60_000,
		});
		await state.lock.publishMarker(state.obsidian);

		await assertDevVaultSymlinks(vaultPath);

		state.plugin = state.obsidian.plugin(PLUGIN_ID);
		state.sandbox = await createSandboxApi({
			obsidian: state.obsidian,
			sandboxRoot: "__obsidian_e2e__",
			testName,
		});

		await state.obsidian.dev.resetDiagnostics().catch(() => undefined);
		await reloadNoteTweet(state.plugin, state.obsidian);
	}, 90_000);

	beforeEach((ctx) => {
		ctx.onTestFailed(async () => {
			if (!state.obsidian) return;

			await captureFailureArtifacts(
				{ id: ctx.task.id, name: ctx.task.name },
				state.obsidian,
				{
					captureOnFailure: true,
					plugin: state.plugin,
				},
			).catch((error) => {
				console.warn("NoteTweet E2E artifact capture failed", error);
			});
		});
	});

	beforeEach(async () => {
		await state.obsidian?.dev.resetDiagnostics().catch(() => undefined);
	});

	afterEach(async () => {
		if (!state.plugin || !state.obsidian) return;

		await restoreNoteTweetData(state.plugin, state.obsidian);
	});

	afterAll(async () => {
		const errors: unknown[] = [];

		await runTeardown("restore plugin data", errors, () => {
			if (!state.plugin || !state.obsidian) return undefined;
			return restoreNoteTweetData(state.plugin, state.obsidian);
		});
		await runTeardown("clean sandbox", errors, () => state.sandbox?.cleanup());
		await runTeardown("clear vault lock marker", errors, () => {
			if (!state.obsidian) return undefined;
			return clearVaultRunLockMarker(state.obsidian);
		});
		await runTeardown("release vault lock", errors, () =>
			state.lock?.release(),
		);

		if (errors.length > 0) {
			throw errors[0];
		}
	}, 30_000);

	return (): NoteTweetE2EContext => {
		if (!state.obsidian || !state.plugin || !state.sandbox) {
			throw new Error("NoteTweet E2E harness is not initialized.");
		}

		return {
			obsidian: state.obsidian,
			plugin: state.plugin,
			sandbox: state.sandbox,
		};
	};
}

export async function reloadNoteTweet(
	plugin: PluginHandle,
	obsidian: ObsidianClient,
): Promise<void> {
	await plugin.reload(RELOAD_OPTIONS);
	await waitForNoteTweetReady(obsidian);
}

export async function restoreNoteTweetData(
	plugin: PluginHandle,
	obsidian: ObsidianClient,
): Promise<void> {
	await plugin.disable();
	await plugin.restoreData();
	await plugin.enable();
	await waitForNoteTweetReady(obsidian);
}

export async function waitForNoteTweetReady(
	obsidian: ObsidianClient,
): Promise<void> {
	await obsidian.waitFor(
		async () => {
			// NoteTweet exposes no public API object, so the loaded plugin instance
			// being present on app.plugins.plugins is the readiness signal.
			return await obsidian.dev.evalJson<boolean>(
				`Boolean(app.plugins.plugins.${PLUGIN_ID})`,
			);
		},
		{
			...WAIT_OPTS,
			message: "NoteTweet plugin did not become ready.",
		},
	);
}

async function assertDevVaultSymlinks(vaultPath: string): Promise<void> {
	const pluginDir = path.join(vaultPath, ".obsidian", "plugins", PLUGIN_ID);

	for (const fileName of PLUGIN_ARTIFACTS) {
		await assertSymlinkTarget(pluginDir, fileName);
	}
}

async function assertSymlinkTarget(
	pluginDir: string,
	fileName: string,
): Promise<void> {
	const linkPath = path.join(pluginDir, fileName);
	const expected = path.join(repoRoot, fileName);
	let target: string;

	try {
		target = await readlink(linkPath);
	} catch (error) {
		throw new Error(
			[
				"NoteTweet E2E preflight failed.",
				`Expected ${linkPath} to be a symlink to ${expected}.`,
				`Could not read symlink: ${error instanceof Error ? error.message : String(error)}`,
			].join(" "),
		);
	}

	const resolvedTarget = path.resolve(path.dirname(linkPath), target);
	if (resolvedTarget !== expected) {
		throw new Error(
			[
				"NoteTweet E2E preflight failed.",
				`Expected ${linkPath} to point at ${expected}.`,
				`It currently points at ${resolvedTarget}.`,
				"Repoint the vault plugin symlink intentionally before running pnpm run test:e2e.",
			].join(" "),
		);
	}
}

async function runTeardown(
	label: string,
	errors: unknown[],
	step: () => Promise<unknown> | unknown,
): Promise<void> {
	try {
		await step();
	} catch (error) {
		errors.push(error);
		console.warn(`NoteTweet E2E teardown failed during ${label}`, error);
	}
}
