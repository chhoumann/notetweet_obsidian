import { describe, expect, test } from "vitest";
import {
	createNoteTweetE2EHarness,
	PLUGIN_ID,
	RELOAD_OPTIONS,
	WAIT_OPTS,
	waitForNoteTweetReady,
} from "./harness";

const getContext = createNoteTweetE2EHarness("notetweet-settings");

/** The pre-modernization credential shape older builds persisted in data.json. */
interface NoteTweetLegacyData {
	apiKey: string;
	apiSecret: string;
	accessToken: string;
	accessTokenSecret: string;
	postTweetTag: string;
	autoSplitTweets: boolean;
	scheduling: { enabled: boolean; url: string };
}

type SettingsSnapshot = {
	found: boolean;
	headings: string[];
	migrationVisible: boolean;
	defaultOptions: Record<string, string>;
};

// Reads the live declarative settings tab (via app.setting.pluginTabs, which is
// populated at load without opening the settings UI) and reports its group
// headings plus whether the "Migrate credentials" group's visibility predicate
// currently resolves true. Non-throwing so it is safe to poll during a reload.
const SETTINGS_SNAPSHOT = `
	(() => {
		const tab = app.setting.pluginTabs.find((t) => t.id === ${JSON.stringify(PLUGIN_ID)});
		if (!tab) return { found: false, headings: [], migrationVisible: false, defaultOptions: {} };
		const definitions = tab.getSettingDefinitions();
		const groupVisible = (group) =>
			typeof group.visible === "function"
				? Boolean(group.visible())
				: group.visible !== false;
		const migration = definitions.find(
			(group) => group.heading === "Migrate credentials",
		);
		const accounts = definitions.find((group) => group.heading === "X accounts");
		const defaultAccount = accounts?.items?.find((item) => item.name === "Default account");
		return {
			found: true,
			headings: definitions.map((group) => group.heading),
			migrationVisible: migration ? groupVisible(migration) : false,
			defaultOptions: defaultAccount?.control?.options ?? {},
		};
	})()
`;

describe("NoteTweet settings tab", () => {
	test("renders the credential, posting, and scheduling groups and hides migration with clean data", async () => {
		const { obsidian } = getContext();

		const snapshot =
			await obsidian.dev.evalJson<SettingsSnapshot>(SETTINGS_SNAPSHOT);

		expect(snapshot.found).toBe(true);
		expect(snapshot.headings).toContain("X accounts");
		expect(snapshot.headings).toContain("Posting");
		expect(snapshot.headings).toContain("Scheduling");
		// The migration group is always part of the definitions; with no legacy
		// credentials its visibility predicate must resolve false so it never
		// renders. This distinguishes "present but hidden" from "absent".
		expect(snapshot.headings).toContain("Migrate credentials");
		expect(snapshot.migrationVisible).toBe(false);
		expect(snapshot.defaultOptions).toEqual({});
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

	test("renders named account groups and the configured default choices", async () => {
		const { obsidian, plugin } = getContext();
		await plugin.updateDataAndReload(
			() => ({
				accounts: [
					{ id: "personal", name: "Personal" },
					{ id: "work", name: "Work" },
				],
				defaultAccountId: "work",
				postTweetTag: "",
				autoSplitTweets: true,
				scheduling: { enabled: false, url: "" },
			}),
			RELOAD_OPTIONS,
		);

		const snapshot =
			await obsidian.dev.evalJson<SettingsSnapshot>(SETTINGS_SNAPSHOT);
		expect(snapshot.headings).toContain("Personal");
		expect(snapshot.headings).toContain("Work");
		expect(snapshot.defaultOptions).toEqual({ personal: "Personal", work: "Work" });
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

	test("reveals the migration group only after legacy plaintext credentials are seeded", async () => {
		const { obsidian, plugin } = getContext();

		// Seed the legacy credential shape into the persisted data file and reload
		// so the tab reads it back. The patch snapshots data.json once, and
		// afterEach's restoreNoteTweetData reverts it for the next test.
		await plugin.updateDataAndReload<NoteTweetLegacyData>(
			() => ({
				apiKey: "ak",
				apiSecret: "as",
				accessToken: "at",
				accessTokenSecret: "ats",
				postTweetTag: "",
				autoSplitTweets: true,
				scheduling: { enabled: false, url: "" },
			}),
			RELOAD_OPTIONS,
		);
		await waitForNoteTweetReady(obsidian);

		await obsidian.waitFor(
			async () =>
				(await obsidian.dev.evalJson<SettingsSnapshot>(SETTINGS_SNAPSHOT))
					.migrationVisible,
			{
				...WAIT_OPTS,
				message:
					"Migration group did not become visible after seeding legacy credentials.",
			},
		);

		const snapshot =
			await obsidian.dev.evalJson<SettingsSnapshot>(SETTINGS_SNAPSHOT);
		expect(snapshot.migrationVisible).toBe(true);
	});

	test("migrates the four fixed secrets into one named account and clears the old keys", async () => {
		const { obsidian, plugin } = getContext();
		const oldIds = {
			apiKey: "notetweet-api-key",
			apiSecret: "notetweet-api-secret",
			accessToken: "notetweet-access-token",
			accessTokenSecret: "notetweet-access-token-secret",
		};
		const newIds = Object.fromEntries(
			Object.entries({
				apiKey: "api-key",
				apiSecret: "api-secret",
				accessToken: "access-token",
				accessTokenSecret: "access-token-secret",
			}).map(([field, suffix]) => [
				field,
				`notetweet-account-migrated-account-${suffix}`,
			]),
		);
		const values = {
			apiKey: "migration-ak",
			apiSecret: "migration-as",
			accessToken: "migration-at",
			accessTokenSecret: "migration-ats",
		};

		try {
			await obsidian.dev.evalJson<boolean>(
				`(() => {
					const ids = ${JSON.stringify(oldIds)};
					const values = ${JSON.stringify(values)};
					for (const key of Object.keys(ids)) app.secretStorage.setSecret(ids[key], values[key]);
					return true;
				})()`,
			);
			await plugin.updateDataAndReload(
				() => ({
					accounts: [],
					defaultAccountId: "",
					postTweetTag: "",
					autoSplitTweets: true,
					scheduling: { enabled: false, url: "" },
				}),
				RELOAD_OPTIONS,
			);

			const result = await obsidian.dev.evalJson<{
				accounts: { id: string; name: string }[];
				defaultAccountId: string;
				oldValues: Record<string, string | null>;
				newValues: Record<string, string | null>;
			}>(
				`(() => {
					const plugin = app.plugins.plugins.${PLUGIN_ID};
					const oldIds = ${JSON.stringify(oldIds)};
					const newIds = ${JSON.stringify(newIds)};
					return {
						accounts: plugin.settings.accounts,
						defaultAccountId: plugin.settings.defaultAccountId,
						oldValues: Object.fromEntries(Object.entries(oldIds).map(([key, id]) => [key, app.secretStorage.getSecret(id)])),
						newValues: Object.fromEntries(Object.entries(newIds).map(([key, id]) => [key, app.secretStorage.getSecret(id)])),
					};
				})()`,
			);

			expect(result.accounts).toEqual([
				{ id: "migrated-account", name: "Default" },
			]);
			expect(result.defaultAccountId).toBe("migrated-account");
			expect(result.newValues).toEqual(values);
			expect(Object.values(result.oldValues).every((value) => value === "")).toBe(
				true,
			);
		} finally {
			await obsidian.dev.evalJson<boolean>(
				`(() => {
					for (const id of [...Object.values(${JSON.stringify(oldIds)}), ...Object.values(${JSON.stringify(newIds)})]) app.secretStorage.setSecret(id, "");
					return true;
				})()`,
			);
		}
	});
});
