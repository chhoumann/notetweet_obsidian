import type { App } from "obsidian";
import CryptoES from "crypto-es";
import { decryptLegacyValue } from "./legacyCrypt";
import {
	type LegacyCredentialData,
	legacyCredentialsEncrypted,
	legacyCredentialsPresent,
	readLegacyCredentials,
	resolveCredentials,
	resolveSchedulerPassword,
	storeCredentials,
	stripLegacyCredentials,
} from "./migration";
import { SECRET_IDS } from "./secrets";

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
	return { app: { secretStorage } as unknown as App, store };
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
	it("returns plaintext values verbatim when no password is given", () => {
		const data: LegacyCredentialData = {
			apiKey: "ak",
			apiSecret: "as",
			accessToken: "at",
			accessTokenSecret: "ats",
			scheduling: { password: "sched-pw" },
		};

		expect(readLegacyCredentials(data)).toEqual({
			apiKey: "ak",
			apiSecret: "as",
			accessToken: "at",
			accessTokenSecret: "ats",
			schedulerPassword: "sched-pw",
		});
	});

	it("decrypts the four Twitter keys but reads the scheduler password as plaintext", () => {
		const password = "migration-pass";
		const encrypt = (value: string) =>
			CryptoES.AES.encrypt(value, password).toString();

		const data: LegacyCredentialData = {
			apiKey: encrypt("ak"),
			apiSecret: encrypt("as"),
			accessToken: encrypt("at"),
			accessTokenSecret: encrypt("ats"),
			secureMode: true,
			// The scheduler password was never encrypted by Secure Mode.
			scheduling: { password: "sched-pw" },
		};

		const result = readLegacyCredentials(data, password);

		expect(result.apiKey).toBe("ak");
		expect(result.apiSecret).toBe("as");
		expect(result.accessToken).toBe("at");
		expect(result.accessTokenSecret).toBe("ats");
		// Must NOT be run through decrypt - kept as the stored plaintext.
		expect(result.schedulerPassword).toBe("sched-pw");
	});
});

describe("decryptLegacyValue", () => {
	// Ciphertext hardcoded from crypto-es 1.2.7 on purpose: a same-version
	// round trip (encrypt + decrypt with the installed library) can never
	// detect a cross-version break, so this fixture pins decrypt
	// compatibility for values users encrypted with the old Secure Mode
	// across crypto-es upgrades.
	it("decrypts a ciphertext produced under crypto-es 1.2.7 (cross-version compatibility pin)", () => {
		const fixtureCiphertext =
			"U2FsdGVkX1+oF0/EozimKUeYHNCJp5s/xIMvUyn04bUvusFwGUi5XHuI6fS2NGfo";
		const password = "correct horse battery staple";

		expect(decryptLegacyValue(fixtureCiphertext, password)).toBe(
			"api-key-1234:secret",
		);
	});
});

describe("storeCredentials", () => {
	it("writes non-empty credentials and skips empty ones", () => {
		const { app, store } = makeApp();

		storeCredentials(app, {
			apiKey: "ak",
			apiSecret: "",
			accessToken: "at",
			accessTokenSecret: "ats",
			schedulerPassword: "sched-pw",
		});

		expect(store.get(SECRET_IDS.apiKey)).toBe("ak");
		expect(store.get(SECRET_IDS.accessToken)).toBe("at");
		expect(store.get(SECRET_IDS.accessTokenSecret)).toBe("ats");
		expect(store.get(SECRET_IDS.schedulerPassword)).toBe("sched-pw");
		// Empty credential is not persisted.
		expect(store.has(SECRET_IDS.apiSecret)).toBe(false);
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

describe("resolveCredentials", () => {
	it("returns SecretStorage credentials when all four are present", () => {
		const { app } = makeApp({
			[SECRET_IDS.apiKey]: "stored-ak",
			[SECRET_IDS.apiSecret]: "stored-as",
			[SECRET_IDS.accessToken]: "stored-at",
			[SECRET_IDS.accessTokenSecret]: "stored-ats",
		});
		// Legacy plaintext also present, but SecretStorage must win.
		const data: LegacyCredentialData = {
			apiKey: "legacy-ak",
			apiSecret: "legacy-as",
			accessToken: "legacy-at",
			accessTokenSecret: "legacy-ats",
		};

		expect(resolveCredentials(app, data)).toEqual({
			apiKey: "stored-ak",
			apiSecret: "stored-as",
			accessToken: "stored-at",
			accessTokenSecret: "stored-ats",
		});
	});

	it("falls back to legacy plaintext when SecretStorage is empty and data is unencrypted", () => {
		const { app } = makeApp();
		const data: LegacyCredentialData = {
			apiKey: "legacy-ak",
			apiSecret: "legacy-as",
			accessToken: "legacy-at",
			accessTokenSecret: "legacy-ats",
		};

		expect(resolveCredentials(app, data)).toEqual({
			apiKey: "legacy-ak",
			apiSecret: "legacy-as",
			accessToken: "legacy-at",
			accessTokenSecret: "legacy-ats",
		});
	});

	it("does not return encrypted legacy values, yielding the empty stored credentials instead", () => {
		const { app } = makeApp();
		const data: LegacyCredentialData = {
			apiKey: "encrypted-ak",
			apiSecret: "encrypted-as",
			accessToken: "encrypted-at",
			accessTokenSecret: "encrypted-ats",
			secureMode: true,
		};

		expect(resolveCredentials(app, data)).toEqual({
			apiKey: "",
			apiSecret: "",
			accessToken: "",
			accessTokenSecret: "",
		});
	});
});

describe("resolveSchedulerPassword", () => {
	it("prefers the stored secret over the legacy password", () => {
		const { app } = makeApp({
			[SECRET_IDS.schedulerPassword]: "stored-pw",
		});
		const data: LegacyCredentialData = {
			scheduling: { password: "legacy-pw" },
		};

		expect(resolveSchedulerPassword(app, data)).toBe("stored-pw");
	});

	it("falls back to the legacy password when unencrypted and unstored", () => {
		const { app } = makeApp();
		const data: LegacyCredentialData = {
			scheduling: { password: "legacy-pw" },
		};

		expect(resolveSchedulerPassword(app, data)).toBe("legacy-pw");
	});

	it("does not fall back to the legacy password under secureMode", () => {
		const { app } = makeApp();
		const data: LegacyCredentialData = {
			secureMode: true,
			scheduling: { password: "legacy-pw" },
		};

		expect(resolveSchedulerPassword(app, data)).toBe("");
	});

	it("returns an empty string when neither source has a password", () => {
		const { app } = makeApp();

		expect(resolveSchedulerPassword(app, {})).toBe("");
	});
});
