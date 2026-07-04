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
};

// Reads the live declarative settings tab (via app.setting.pluginTabs, which is
// populated at load without opening the settings UI) and reports its group
// headings plus whether the "Migrate credentials" group's visibility predicate
// currently resolves true. Non-throwing so it is safe to poll during a reload.
const SETTINGS_SNAPSHOT = `
	(() => {
		const tab = app.setting.pluginTabs.find((t) => t.id === ${JSON.stringify(PLUGIN_ID)});
		if (!tab) return { found: false, headings: [], migrationVisible: false };
		const definitions = tab.getSettingDefinitions();
		const groupVisible = (group) =>
			typeof group.visible === "function"
				? Boolean(group.visible())
				: group.visible !== false;
		const migration = definitions.find(
			(group) => group.heading === "Migrate credentials",
		);
		return {
			found: true,
			headings: definitions.map((group) => group.heading),
			migrationVisible: migration ? groupVisible(migration) : false,
		};
	})()
`;

describe("NoteTweet settings tab", () => {
	test("renders the credential, posting, and scheduling groups and hides migration with clean data", async () => {
		const { obsidian } = getContext();

		const snapshot =
			await obsidian.dev.evalJson<SettingsSnapshot>(SETTINGS_SNAPSHOT);

		expect(snapshot.found).toBe(true);
		expect(snapshot.headings).toContain("Twitter API credentials");
		expect(snapshot.headings).toContain("Posting");
		expect(snapshot.headings).toContain("Scheduling");
		// The migration group is always part of the definitions; with no legacy
		// credentials its visibility predicate must resolve false so it never
		// renders. This distinguishes "present but hidden" from "absent".
		expect(snapshot.headings).toContain("Migrate credentials");
		expect(snapshot.migrationVisible).toBe(false);
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
});
