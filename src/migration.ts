import type { App } from "obsidian";
import {
	LEGACY_TWITTER_SECRET_IDS,
	SECRET_IDS,
	getSecret,
	setAccountCredentials,
	setSecret,
	type TwitterCredentials,
} from "./secrets";
import type { NoteTweetSettings, XAccount } from "./settings";
import { decryptLegacyValue } from "./legacyCrypt";

/**
 * Shape of the credential fields that older versions of the plugin persisted in
 * `data.json`. These are read only for the one-time migration into
 * SecretStorage and are stripped once migrated.
 */
export interface LegacyCredentialData {
	apiKey?: string;
	apiSecret?: string;
	accessToken?: string;
	accessTokenSecret?: string;
	/** True when the four keys above are AES-encrypted (old "Secure Mode"). */
	secureMode?: boolean;
	scheduling?: { password?: string; [key: string]: unknown };
	[key: string]: unknown;
}

export interface MigratableCredentials extends TwitterCredentials {
	schedulerPassword: string;
}

export function legacyCredentialsPresent(data: LegacyCredentialData): boolean {
	return Boolean(
		data.apiKey ||
			data.apiSecret ||
			data.accessToken ||
			data.accessTokenSecret ||
			data.scheduling?.password,
	);
}

export function legacyCredentialsEncrypted(data: LegacyCredentialData): boolean {
	return legacyCredentialsPresent(data) && Boolean(data.secureMode);
}

/**
 * Read the legacy credentials, decrypting the four Twitter keys with `password`
 * when they were stored under Secure Mode (throws if the password is wrong).
 * The scheduler password was never encrypted, so it is always read plaintext.
 */
export function readLegacyCredentials(
	data: LegacyCredentialData,
	password?: string,
): MigratableCredentials {
	const decode = (value?: string): string => {
		if (!value) return "";
		return password ? decryptLegacyValue(value, password) : value;
	};

	return {
		apiKey: decode(data.apiKey),
		apiSecret: decode(data.apiSecret),
		accessToken: decode(data.accessToken),
		accessTokenSecret: decode(data.accessTokenSecret),
		schedulerPassword: data.scheduling?.password ?? "",
	};
}

/** Write the migrated (already-decrypted) credentials into SecretStorage. */
export function storeCredentials(
	app: App,
	accountId: string,
	credentials: MigratableCredentials,
): void {
	setAccountCredentials(app, accountId, credentials);
	if (credentials.schedulerPassword)
		setSecret(app, SECRET_IDS.schedulerPassword, credentials.schedulerPassword);
}

const MIGRATED_ACCOUNT_ID = "migrated-account";

/**
 * Copy the four fixed SecretStorage values used by NoteTweet 0.6 into one
 * named account. The old keys are deliberately cleared only after settings
 * metadata has been saved by the caller.
 */
export function stageFixedSecretMigration(
	app: App,
	settings: NoteTweetSettings,
): XAccount | null {
	const credentials: TwitterCredentials = {
		apiKey: getSecret(app, LEGACY_TWITTER_SECRET_IDS.apiKey),
		apiSecret: getSecret(app, LEGACY_TWITTER_SECRET_IDS.apiSecret),
		accessToken: getSecret(app, LEGACY_TWITTER_SECRET_IDS.accessToken),
		accessTokenSecret: getSecret(
			app,
			LEGACY_TWITTER_SECRET_IDS.accessTokenSecret,
		),
	};
	if (!Object.values(credentials).some(Boolean)) return null;

	let account = settings.accounts.find(
		(candidate) => candidate.id === MIGRATED_ACCOUNT_ID,
	);
	if (!account) {
		account = {
			id: MIGRATED_ACCOUNT_ID,
			name: settings.accounts.length === 0 ? "Default" : "Imported account",
		};
		settings.accounts.push(account);
	}
	if (!settings.accounts.some(({ id }) => id === settings.defaultAccountId)) {
		settings.defaultAccountId = account.id;
	}
	setAccountCredentials(app, account.id, credentials);
	return account;
}

export function clearFixedTwitterSecrets(app: App): void {
	for (const id of Object.values(LEGACY_TWITTER_SECRET_IDS)) {
		setSecret(app, id, "");
	}
}

/** Remove the legacy credential fields from the persisted settings object. */
export function stripLegacyCredentials(data: LegacyCredentialData): void {
	delete data.apiKey;
	delete data.apiSecret;
	delete data.accessToken;
	delete data.accessTokenSecret;
	delete data.secureMode;
	if (data.scheduling) delete data.scheduling.password;
}

export function resolveSchedulerPassword(
	app: App,
	data: LegacyCredentialData,
): string {
	const stored = app.secretStorage?.getSecret(SECRET_IDS.schedulerPassword);
	if (stored) return stored;
	if (!data.secureMode && data.scheduling?.password) {
		return data.scheduling.password;
	}
	return "";
}
