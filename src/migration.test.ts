import type { App } from "obsidian";
import { decryptLegacyValue } from "./legacyCrypt";
import {
	assignSchedulerPasswordKey,
	type LegacyCredentialData,
	legacyCredentialsEncrypted,
	legacyCredentialsPresent,
	readLegacyCredentials,
	resolveSchedulerPassword,
	setSchedulerPassword,
	stageFixedSecretMigration,
	clearFixedTwitterSecrets,
	storeCredentials,
	stripLegacyCredentials,
} from "./migration";
import {
	LEGACY_SCHEDULER_PASSWORD_ID,
	LEGACY_TWITTER_SECRET_IDS,
	accountSecretId,
	getAccountCredentials,
	schedulerPasswordSecretId,
} from "./secrets";
import { DEFAULT_SETTINGS, type NoteTweetSettings } from "./settings";

const PASSWORD_KEY = "0123456789abcdef01234567";

/** Vault settings as NoteTweet loads them, plus any legacy fields. */
function vaultSettings(
	scheduling: Partial<NoteTweetSettings["scheduling"]> & { password?: string } = {},
	legacy: Partial<LegacyCredentialData> = {},
): NoteTweetSettings {
	return {
		...structuredClone(DEFAULT_SETTINGS),
		...legacy,
		scheduling: { ...DEFAULT_SETTINGS.scheduling, passwordKey: PASSWORD_KEY, ...scheduling },
	} as NoteTweetSettings;
}

interface FakeSecretStorage {
	getSecret(id: string): string | null;
	setSecret(id: string, value: string): void;
	listSecrets(): string[];
}

// Runtime secret collection: keys are written at test time and iterated back,
// which is exactly what a Map is for.
function makeApp(initial: Record<string, string> = {}): {
	app: App;
	store: Map<string, string>;
} {
	const store = new Map<string, string>(Object.entries(initial));
	const secretStorage: FakeSecretStorage = {
		getSecret: (id) => store.get(id) ?? null,
		setSecret: (id, value) => {
			store.set(id, value);
		},
		listSecrets: () => [...store.keys()],
	};
	const local = new Map<string, unknown>();
	const app = {
		secretStorage,
		loadLocalStorage: (key: string) => local.get(key) ?? null,
		saveLocalStorage: (key: string, value: unknown) => local.set(key, value),
	};
	return { app: app as unknown as App, store };
}

describe("legacyCredentialsPresent", () => {
	it("is true when any Twitter key is set", () => {
		expect(legacyCredentialsPresent({ accessToken: "at" })).toBe(true);
	});

	it("is true when only the scheduler password is set", () => {
		expect(
			legacyCredentialsPresent({ scheduling: { password: "pw" } }),
		).toBe(true);
	});

	it("is false for empty data", () => {
		expect(legacyCredentialsPresent({})).toBe(false);
	});
});

describe("legacyCredentialsEncrypted", () => {
	it("is true only when credentials are present and secureMode is on", () => {
		expect(
			legacyCredentialsEncrypted({ apiKey: "ak", secureMode: true }),
		).toBe(true);
	});

	it("is false when present but secureMode is off", () => {
		expect(legacyCredentialsEncrypted({ apiKey: "ak" })).toBe(false);
	});

	it("is false when secureMode is on but no credentials exist", () => {
		expect(legacyCredentialsEncrypted({ secureMode: true })).toBe(false);
	});
});

describe("readLegacyCredentials", () => {
	it("returns plaintext values verbatim when no password is given", async () => {
		const data: LegacyCredentialData = {
			apiKey: "ak",
			apiSecret: "as",
			accessToken: "at",
			accessTokenSecret: "ats",
			scheduling: { password: "sched-pw" },
		};

		await expect(readLegacyCredentials(data)).resolves.toEqual({
			apiKey: "ak",
			apiSecret: "as",
			accessToken: "at",
			accessTokenSecret: "ats",
			schedulerPassword: "sched-pw",
		});
	});

	it("decrypts the four Twitter keys but reads the scheduler password as plaintext", async () => {
		// Encrypted with `openssl enc -aes-256-cbc -md md5 -pass pass:migration-pass`.
		const password = "migration-pass";
		const data: LegacyCredentialData = {
			apiKey: "U2FsdGVkX19ytuAALII+VARJip+9yIw0ip0GiORnltg=",
			apiSecret: "U2FsdGVkX1+TZdVBuf1wMOx6ba7NZ6zle/rMK0y93uc=",
			accessToken: "U2FsdGVkX1+m6hSg59TOht37qR7SixRkfkm70lMzyLk=",
			accessTokenSecret: "U2FsdGVkX18Zxe2F4wfkFY6dcq2wB174ct0VJs5AhcQ=",
			secureMode: true,
			// The scheduler password was never encrypted by Secure Mode.
			scheduling: { password: "sched-pw" },
		};

		const result = await readLegacyCredentials(data, password);

		expect(result.apiKey).toBe("ak");
		expect(result.apiSecret).toBe("as");
		expect(result.accessToken).toBe("at");
		expect(result.accessTokenSecret).toBe("ats");
		// Must NOT be run through decrypt - kept as the stored plaintext.
		expect(result.schedulerPassword).toBe("sched-pw");
	});
});

describe("decryptLegacyValue", () => {
	// Ciphertexts come from independent implementations on purpose: crypto-es
	// 1.2.7 (what old Secure Mode wrote) and the OpenSSL CLI
	// (`openssl enc -aes-256-cbc -md md5 -salt -pass pass:<password>`).
	it("decrypts a ciphertext produced under crypto-es 1.2.7", async () => {
		await expect(
			decryptLegacyValue(
				"U2FsdGVkX1+oF0/EozimKUeYHNCJp5s/xIMvUyn04bUvusFwGUi5XHuI6fS2NGfo",
				"correct horse battery staple",
			),
		).resolves.toBe("api-key-1234:secret");
	});

	it.each([
		["ak", "pw", "U2FsdGVkX1+QVc3vsMD3kelrd7W6wBBa8DVXcHUz4FM="],
		["at", "pässwörd 🔑", "U2FsdGVkX1+W30OnWTWWPhSFXVy/THLyfcbiYLLvIiI="],
		["ats", "p".repeat(60), "U2FsdGVkX1/NZs76lENWuRfJbot0vQTeEF73GB4k1n8="],
		[
			"1234567890-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP",
			"x",
			"U2FsdGVkX19ifA6156ssNjBzgEtCutZ7sOAB59PhOTI8pCpZfFRSblJ3e78IZkjFEqy/NHrfgrN/iV0dy5Klt/o/xX6xhmPSa4JOe2+F5o4=",
		],
	])("decrypts OpenSSL ciphertext of %j", async (plaintext, password, ciphertext) => {
		await expect(decryptLegacyValue(ciphertext, password)).resolves.toBe(plaintext);
	});

	it("rejects a wrong password", async () => {
		await expect(
			decryptLegacyValue(
				"U2FsdGVkX1+oF0/EozimKUeYHNCJp5s/xIMvUyn04bUvusFwGUi5XHuI6fS2NGfo",
				"wrong password",
			),
		).rejects.toThrow();
	});
});

describe("storeCredentials", () => {
	it("writes credentials into one account namespace", () => {
		const { app, store } = makeApp();

		storeCredentials(app, vaultSettings(), "personal", {
			apiKey: "ak",
			apiSecret: "",
			accessToken: "at",
			accessTokenSecret: "ats",
			schedulerPassword: "sched-pw",
		});

		expect(store.get(accountSecretId("personal", "apiKey"))).toBe("ak");
		expect(store.get(accountSecretId("personal", "accessToken"))).toBe("at");
		expect(store.get(accountSecretId("personal", "accessTokenSecret"))).toBe(
			"ats",
		);
		expect(store.get(schedulerPasswordSecretId(PASSWORD_KEY))).toBe("sched-pw");
		expect(store.get(accountSecretId("personal", "apiSecret"))).toBe("");
		expect(store.has("notetweet-account-personal-undefined")).toBe(false);
	});
});

describe("stripLegacyCredentials", () => {
	it("removes credential fields while preserving unrelated settings", () => {
		const data: LegacyCredentialData = {
			apiKey: "ak",
			apiSecret: "as",
			accessToken: "at",
			accessTokenSecret: "ats",
			secureMode: true,
			scheduling: { password: "sched-pw", url: "https://scheduler.example" },
			postTweetTag: "#tweeted",
		};

		stripLegacyCredentials(data);

		expect("apiKey" in data).toBe(false);
		expect("apiSecret" in data).toBe(false);
		expect("accessToken" in data).toBe(false);
		expect("accessTokenSecret" in data).toBe(false);
		expect("secureMode" in data).toBe(false);
		expect(data.scheduling && "password" in data.scheduling).toBe(false);
		// Unrelated settings survive.
		expect(data.scheduling?.url).toBe("https://scheduler.example");
		expect(data.postTweetTag).toBe("#tweeted");
	});
});

describe("fixed SecretStorage migration", () => {
	it("copies all four fixed secrets into a named default account", () => {
		const { app } = makeApp({
			[LEGACY_TWITTER_SECRET_IDS.apiKey]: "stored-ak",
			[LEGACY_TWITTER_SECRET_IDS.apiSecret]: "stored-as",
			[LEGACY_TWITTER_SECRET_IDS.accessToken]: "stored-at",
			[LEGACY_TWITTER_SECRET_IDS.accessTokenSecret]: "stored-ats",
		});
		const settings = structuredClone(DEFAULT_SETTINGS);

		const account = stageFixedSecretMigration(app, settings);

		expect(account).toEqual({ id: "migrated-account", name: "Default" });
		expect(settings.accounts).toEqual([account]);
		expect(settings.defaultAccountId).toBe(account?.id);
		expect(getAccountCredentials(app, account?.id ?? "")).toEqual({
			apiKey: "stored-ak",
			apiSecret: "stored-as",
			accessToken: "stored-at",
			accessTokenSecret: "stored-ats",
		});
	});

	it("is idempotent and clears fixed secrets only when explicitly finalized", () => {
		const { app, store } = makeApp({
			[LEGACY_TWITTER_SECRET_IDS.apiKey]: "stored-ak",
		});
		const settings = structuredClone(DEFAULT_SETTINGS);

		stageFixedSecretMigration(app, settings);
		stageFixedSecretMigration(app, settings);
		expect(settings.accounts).toHaveLength(1);
		expect(store.get(LEGACY_TWITTER_SECRET_IDS.apiKey)).toBe("stored-ak");

		clearFixedTwitterSecrets(app);
		expect(store.get(LEGACY_TWITTER_SECRET_IDS.apiKey)).toBe("");
	});
});

describe("resolveSchedulerPassword", () => {
	it("prefers the stored secret over the legacy password", () => {
		const { app } = makeApp({
			[schedulerPasswordSecretId(PASSWORD_KEY)]: "stored-pw",
		});

		expect(resolveSchedulerPassword(app, vaultSettings({ password: "legacy-pw" }))).toBe(
			"stored-pw",
		);
	});

	it("falls back to the legacy password when unencrypted and unstored", () => {
		const { app } = makeApp();

		expect(resolveSchedulerPassword(app, vaultSettings({ password: "legacy-pw" }))).toBe(
			"legacy-pw",
		);
	});

	it("does not fall back to the legacy password under secureMode", () => {
		const { app } = makeApp();
		const settings = vaultSettings({ password: "legacy-pw" }, { secureMode: true });

		expect(resolveSchedulerPassword(app, settings)).toBe("");
	});

	it("returns an empty string when neither source has a password", () => {
		const { app } = makeApp();

		expect(resolveSchedulerPassword(app, vaultSettings())).toBe("");
	});
});

describe("per-vault scheduler password", () => {
	/** A vault as NoteTweet 0.7.0 left it, upgraded on load. */
	function upgraded(app: App, scheduling: Partial<NoteTweetSettings["scheduling"]>) {
		const settings = vaultSettings({ passwordKey: "", ...scheduling });
		expect(assignSchedulerPasswordKey(settings)).toBe(true);
		expect(assignSchedulerPasswordKey(settings)).toBe(false);
		return settings;
	}

	it("keeps an upgraded vault's password without copying any secret", () => {
		const { app, store } = makeApp({ [LEGACY_SCHEDULER_PASSWORD_ID]: "shared-pw" });
		const settings = upgraded(app, { enabled: true, url: "https://a" });

		expect(settings.scheduling.passwordKey).toMatch(/^[a-f0-9]{24}$/);
		expect(resolveSchedulerPassword(app, settings)).toBe("shared-pw");
		expect([...store.keys()]).toEqual([LEGACY_SCHEDULER_PASSWORD_ID]);
	});

	it("does not hand the old shared password to a vault without a scheduler", () => {
		const { app } = makeApp({ [LEGACY_SCHEDULER_PASSWORD_ID]: "shared-pw" });
		const settings = upgraded(app, {});
		settings.scheduling.enabled = true;

		expect(resolveSchedulerPassword(app, settings)).toBe("");
	});

	it("keeps each vault's password separate in shared storage", () => {
		const { app } = makeApp({ [LEGACY_SCHEDULER_PASSWORD_ID]: "shared-pw" });
		const vaultA = upgraded(app, { enabled: true, url: "https://a" });
		const vaultB = upgraded(app, { enabled: true, url: "https://b" });

		setSchedulerPassword(app, vaultA, "pw-a");
		setSchedulerPassword(app, vaultB, "pw-b");

		expect(resolveSchedulerPassword(app, vaultA)).toBe("pw-a");
		expect(resolveSchedulerPassword(app, vaultB)).toBe("pw-b");
	});

	it("never revives the old password once the user clears theirs", () => {
		const { app } = makeApp({ [LEGACY_SCHEDULER_PASSWORD_ID]: "shared-pw" });
		const settings = upgraded(app, { enabled: true, url: "https://a" });

		setSchedulerPassword(app, settings, "");
		settings.scheduling.url = "https://elsewhere";

		expect(resolveSchedulerPassword(app, settings)).toBe("");
	});

	it("reads each device's own old password when data.json syncs", () => {
		const desktop = makeApp({ [LEGACY_SCHEDULER_PASSWORD_ID]: "desktop-pw" });
		const phone = makeApp({ [LEGACY_SCHEDULER_PASSWORD_ID]: "phone-pw" });
		const settings = upgraded(desktop.app, { enabled: true, url: "https://a" });
		setSchedulerPassword(desktop.app, settings, "new-desktop-pw");

		const synced = structuredClone(settings);

		expect(resolveSchedulerPassword(desktop.app, settings)).toBe("new-desktop-pw");
		expect(resolveSchedulerPassword(phone.app, synced)).toBe("phone-pw");
	});
});
