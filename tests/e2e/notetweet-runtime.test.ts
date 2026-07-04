import { describe, expect, test } from "vitest";
import {
	createNoteTweetE2EHarness,
	evalJsonAsync,
	PLUGIN_ID,
	WAIT_OPTS,
} from "./harness";

const getContext = createNoteTweetE2EHarness("notetweet-runtime");

describe("NoteTweet runtime", () => {
	test("registers its three production commands and omits the dev reload command", async () => {
		const { obsidian } = getContext();

		const commandIds = await obsidian.dev.evalJson<string[]>(
			`Object.keys(app.commands?.commands ?? {})
				.filter((id) => id.startsWith(${JSON.stringify(`${PLUGIN_ID}:`)}))
				.sort()`,
		);

		expect(commandIds).toContain(`${PLUGIN_ID}:post-tweet`);
		expect(commandIds).toContain(`${PLUGIN_ID}:post-selected-as-tweet`);
		expect(commandIds).toContain(`${PLUGIN_ID}:post-file-as-thread`);
		// The dev-only "Reload (dev)" command lives inside START.DEVCMD/END.DEVCMD
		// markers that esbuild strips from the production bundle, so a shipped
		// build must never expose it.
		expect(commandIds).not.toContain(`${PLUGIN_ID}:reload`);
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

	test("exposes SecretStorage that round-trips a secret on the live runtime", async () => {
		const { obsidian } = getContext();

		const probeId = "notetweet-e2e-probe";
		const probeValue = "notetweet-e2e-secret-value";

		const result = await evalJsonAsync<{
			hasSetSecret: boolean;
			hasGetSecret: boolean;
			hasListSecrets: boolean;
			readBack: string | null;
			listedAfterSet: boolean;
		}>(
			obsidian,
			`
			(async () => {
				const storage = app.secretStorage;
				const probeId = ${JSON.stringify(probeId)};
				const probeValue = ${JSON.stringify(probeValue)};

				const hasSetSecret = typeof storage?.setSecret === "function";
				const hasGetSecret = typeof storage?.getSecret === "function";
				const hasListSecrets = typeof storage?.listSecrets === "function";

				await storage.setSecret(probeId, probeValue);
				const readBack = await storage.getSecret(probeId);
				const listedAfterSet = (await storage.listSecrets()).includes(probeId);

				// Blank the throwaway secret so no per-run state leaks into the vault.
				await storage.setSecret(probeId, "");

				return { hasSetSecret, hasGetSecret, hasListSecrets, readBack, listedAfterSet };
			})()
			`,
		);

		expect(result.hasSetSecret).toBe(true);
		expect(result.hasGetSecret).toBe(true);
		expect(result.hasListSecrets).toBe(true);
		// The value written under SecretStorage must survive a real read-back:
		// this is the core assumption the credential modernization relies on.
		expect(result.readBack).toBe(probeValue);
		expect(result.listedAfterSet).toBe(true);
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

	test("opens the compose-tweet modal for the post-tweet command and closes it", async () => {
		const { obsidian } = getContext();

		const modalSelector = ".postTweetModal textarea.tweetArea";

		// Fire the user-facing command; its callback opens ComposeTweetModal, whose
		// content root carries the postTweetModal class and a tweetArea textarea.
		await obsidian.dev.evalJson<boolean>(
			`app.commands.executeCommandById(${JSON.stringify(`${PLUGIN_ID}:post-tweet`)})`,
		);

		await obsidian.waitFor(
			() =>
				obsidian.dev.evalJson<boolean>(
					`Boolean(document.querySelector(${JSON.stringify(modalSelector)}))`,
				),
			{ ...WAIT_OPTS, message: "Compose tweet modal did not open." },
		);

		const hasTextarea = await obsidian.dev.evalJson<boolean>(
			`Boolean(document.querySelector(${JSON.stringify(modalSelector)}))`,
		);
		expect(hasTextarea).toBe(true);

		// Dismiss the composer through the active modal handle, mirroring how the
		// metaedit modal suite closes Obsidian modals.
		await obsidian.dev.evalJson<boolean>(
			`(app.workspace.activeModal?.close?.(), true)`,
		);

		await obsidian.waitFor(
			() =>
				obsidian.dev.evalJson<boolean>(
					`document.querySelector(".postTweetModal") === null`,
				),
			{ ...WAIT_OPTS, message: "Compose tweet modal did not close." },
		);

		const closed = await obsidian.dev.evalJson<boolean>(
			`document.querySelector(".postTweetModal") === null`,
		);
		expect(closed).toBe(true);
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});
});
