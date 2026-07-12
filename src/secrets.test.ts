import type { App } from "obsidian";
import {
	accountSecretId,
	getSecret,
	getAccountCredentials,
	hasCompleteCredentials,
	hasSecretStorage,
	setSecret,
	type TwitterCredentials,
} from "./secrets";

interface FakeSecretStorage {
	getSecret(id: string): string | null;
	setSecret(id: string, value: string): void;
	listSecrets(): string[];
}

function makeApp(initial: Record<string, string> = {}): App {
	const store = new Map<string, string>(Object.entries(initial));
	const secretStorage: FakeSecretStorage = {
		getSecret: (id) => store.get(id) ?? null,
		setSecret: (id, value) => {
			store.set(id, value);
		},
		listSecrets: () => [...store.keys()],
	};
	return { secretStorage } as unknown as App;
}

const completeCredentials: TwitterCredentials = {
	apiKey: "ak",
	apiSecret: "as",
	accessToken: "at",
	accessTokenSecret: "ats",
};

describe("hasSecretStorage", () => {
	it("is true when secretStorage exposes getSecret and setSecret", () => {
		expect(hasSecretStorage(makeApp())).toBe(true);
	});

	it("is false when secretStorage is absent", () => {
		expect(hasSecretStorage({} as unknown as App)).toBe(false);
	});

	it("is false when secretStorage lacks the required methods", () => {
		const missingBoth = { secretStorage: {} } as unknown as App;
		const missingSetter = {
			secretStorage: { getSecret: () => null },
		} as unknown as App;

		expect(hasSecretStorage(missingBoth)).toBe(false);
		expect(hasSecretStorage(missingSetter)).toBe(false);
	});
});

describe("getSecret / setSecret", () => {
	it("round-trips a stored value", () => {
		const app = makeApp();

		setSecret(app, accountSecretId("personal", "apiKey"), "secret-value");

		expect(getSecret(app, accountSecretId("personal", "apiKey"))).toBe(
			"secret-value",
		);
	});

	it("returns an empty string for an unset id", () => {
		expect(
			getSecret(makeApp(), accountSecretId("personal", "apiSecret")),
		).toBe("");
	});
});

describe("getAccountCredentials", () => {
	it("reads four credentials scoped to the requested account", () => {
		const app = makeApp({
			[accountSecretId("personal", "apiKey")]: "ak",
			[accountSecretId("personal", "apiSecret")]: "as",
			[accountSecretId("personal", "accessToken")]: "at",
			[accountSecretId("personal", "accessTokenSecret")]: "ats",
			[accountSecretId("work", "apiKey")]: "other-ak",
		});

		expect(getAccountCredentials(app, "personal")).toEqual({
			apiKey: "ak",
			apiSecret: "as",
			accessToken: "at",
			accessTokenSecret: "ats",
		});
	});
});

describe("hasCompleteCredentials", () => {
	it("is true only when all four fields are non-empty", () => {
		expect(hasCompleteCredentials(completeCredentials)).toBe(true);
	});

	it("is false when any single field is empty", () => {
		for (const field of Object.keys(
			completeCredentials,
		) as (keyof TwitterCredentials)[]) {
			expect(
				hasCompleteCredentials({ ...completeCredentials, [field]: "" }),
			).toBe(false);
		}
	});
});
