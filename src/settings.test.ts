import {
	DEFAULT_SETTINGS,
	normalizeAccountSettings,
	type NoteTweetSettings,
} from "./settings";

describe("normalizeAccountSettings", () => {
	it("preserves valid account metadata and its default", () => {
		const settings: NoteTweetSettings = {
			...structuredClone(DEFAULT_SETTINGS),
			accounts: [
				{ id: "personal", name: " Personal " },
				{ id: "work-account", name: "Work" },
			],
			defaultAccountId: "work-account",
		};

		normalizeAccountSettings(settings);

		expect(settings.accounts).toEqual([
			{ id: "personal", name: "Personal" },
			{ id: "work-account", name: "Work" },
		]);
		expect(settings.defaultAccountId).toBe("work-account");
	});

	it("drops unsafe or duplicate metadata and repairs an invalid default", () => {
		const settings = {
			...structuredClone(DEFAULT_SETTINGS),
			accounts: [
				{ id: "personal", name: "Personal" },
				{ id: "personal", name: "Duplicate" },
				{ id: "../unsafe", name: "Unsafe" },
				{ id: "blank-name", name: "  " },
			],
			defaultAccountId: "missing",
		};

		normalizeAccountSettings(settings);

		expect(settings.accounts).toEqual([
			{ id: "personal", name: "Personal" },
		]);
		expect(settings.defaultAccountId).toBe("personal");
	});
});
