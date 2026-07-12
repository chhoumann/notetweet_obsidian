import {
	createAccount,
	DEFAULT_SETTINGS,
	normalizeAccountSettings,
	type NoteTweetSettings,
} from "./settings";
import {
	accountSecretId,
	MAX_ACCOUNT_ID_LENGTH,
	type TwitterCredentials,
} from "./secrets";

const CREDENTIAL_FIELDS: (keyof TwitterCredentials)[] = [
	"apiKey",
	"apiSecret",
	"accessToken",
	"accessTokenSecret",
];

describe("createAccount", () => {
	it("generates an opaque id that keeps every SecretStorage key within 64 characters", () => {
		const account = createAccount(" Personal ");

		expect(account).toEqual({
			id: expect.stringMatching(/^[a-f0-9]{24}$/),
			name: "Personal",
		});
		expect(account.id).toHaveLength(24);
		for (const field of CREDENTIAL_FIELDS) {
			expect(accountSecretId(account.id, field).length).toBeLessThanOrEqual(64);
		}
	});
});

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
				{ id: "a".repeat(MAX_ACCOUNT_ID_LENGTH + 1), name: "Too long" },
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
