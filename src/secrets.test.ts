import type { App } from "obsidian";
import {
	SECRET_IDS,
	getSecret,
	getTwitterCredentials,
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

		setSecret(app, SECRET_IDS.apiKey, "secret-value");

		expect(getSecret(app, SECRET_IDS.apiKey)).toBe("secret-value");
	});

	it("returns an empty string for an unset id", () => {
		expect(getSecret(makeApp(), SECRET_IDS.apiSecret)).toBe("");
	});
});

describe("getTwitterCredentials", () => {
	it("reads the four Twitter secret ids into a credentials object", () => {
		const app = makeApp({
			[SECRET_IDS.apiKey]: "ak",
			[SECRET_IDS.apiSecret]: "as",
			[SECRET_IDS.accessToken]: "at",
			[SECRET_IDS.accessTokenSecret]: "ats",
			// The scheduler password lives outside TwitterCredentials.
			[SECRET_IDS.schedulerPassword]: "should-not-appear",
		});

		expect(getTwitterCredentials(app)).toEqual({
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
