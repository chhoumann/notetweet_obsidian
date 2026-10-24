import { MAX_ACCOUNT_ID_LENGTH } from "./secrets";

export interface XAccount {
	id: string;
	name: string;
}

export interface NoteTweetSettings {
	/** Named X accounts. Credentials live separately in SecretStorage. */
	accounts: XAccount[];
	/** Account used by commands that do not show the composer. */
	defaultAccountId: string;
	/** Tag appended to a note's text after its tweet is posted (empty = off). */
	postTweetTag: string;
	/** Split pasted/typed content into multiple tweets at the 280-char limit. */
	autoSplitTweets: boolean;
	scheduling: {
		enabled: boolean;
		url: string;
		/** Keys this vault's scheduler password in the shared secret storage. */
		passwordKey: string;
		/** Used a scheduler before 0.7.1, so it may still read the old shared password. */
		legacyPassword: boolean;
	};
}

export const DEFAULT_SETTINGS: NoteTweetSettings = {
	accounts: [],
	defaultAccountId: "",
	postTweetTag: "",
	autoSplitTweets: true,
	scheduling: {
		enabled: false,
		url: "",
		passwordKey: "",
		legacyPassword: false,
	},
};

const ACCOUNT_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const ACCOUNT_ID_BYTES = 12;

/** Keep persisted account metadata safe for use in SecretStorage identifiers. */
export function normalizeAccountSettings(settings: NoteTweetSettings): void {
	const seen = new Set<string>();
	settings.accounts = Array.isArray(settings.accounts)
		? settings.accounts.filter((account): account is XAccount => {
			if (
				!account ||
				typeof account.id !== "string" ||
				account.id.length > MAX_ACCOUNT_ID_LENGTH ||
				!ACCOUNT_ID.test(account.id) ||
				typeof account.name !== "string" ||
				account.name.trim() === "" ||
				seen.has(account.id)
			) {
				return false;
			}
			seen.add(account.id);
			account.name = account.name.trim();
			return true;
		})
		: [];

	if (!seen.has(settings.defaultAccountId)) {
		settings.defaultAccountId = settings.accounts[0]?.id ?? "";
	}
}

/** A random lowercase hex id that is safe inside SecretStorage identifiers. */
export function randomId(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(ACCOUNT_ID_BYTES));
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function createAccount(name: string): XAccount {
	return { id: randomId(), name: name.trim() };
}
