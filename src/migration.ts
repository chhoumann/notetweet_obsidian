import type { App } from "obsidian";
import {
	LEGACY_SCHEDULER_PASSWORD_ID,
	LEGACY_TWITTER_SECRET_IDS,
	getSecret,
	schedulerPasswordSecretId,
	setAccountCredentials,
	setSecret,
	type TwitterCredentials,
} from "./secrets";
import { randomId, type NoteTweetSettings, type XAccount } from "./settings";
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
 * when they were stored under Secure Mode (rejects if the password is wrong).
 * The scheduler password was never encrypted, so it is always read plaintext.
 */
export async function readLegacyCredentials(
	data: LegacyCredentialData,
	password?: string,
): Promise<MigratableCredentials> {
	const decode = async (value?: string): Promise<string> => {
		if (!value) return "";
		return password ? decryptLegacyValue(value, password) : value;
	};

	const [apiKey, apiSecret, accessToken, accessTokenSecret] = await Promise.all([
		decode(data.apiKey),
		decode(data.apiSecret),
		decode(data.accessToken),
		decode(data.accessTokenSecret),
	]);
	return {
		apiKey,
		apiSecret,
		accessToken,
		accessTokenSecret,
		schedulerPassword: data.scheduling?.password ?? "",
	};
}

/** Write the migrated (already-decrypted) credentials into SecretStorage. */
export function storeCredentials(
	app: App,
	settings: NoteTweetSettings,
	accountId: string,
	credentials: MigratableCredentials,
): void {
	setAccountCredentials(app, accountId, credentials);
	// A password already set for this vault here is newer than the legacy one.
	if (credentials.schedulerPassword && !app.loadLocalStorage(passwordSetHere(settings)))
		setSchedulerPassword(app, settings, credentials.schedulerPassword);
}

const PASSWORD_KEY = /^[a-f0-9]+$/;

/** Device-local marker: this vault's scheduler password was set on this device. */
function passwordSetHere(settings: NoteTweetSettings): string {
	return `notetweet-scheduler-password-set-${settings.scheduling.passwordKey}`;
}

/**
 * Give this vault its own scheduler password secret. Secret storage is shared
 * by every vault on a device, and NoteTweet 0.7.0 kept the scheduler password
 * under one fixed id, so vaults pointing at different schedulers overwrote each
 * other's password. A vault that already used a scheduler is marked so it keeps
 * reading that old password until one is set for it. Returns true when the
 * settings changed and need saving.
 */
export function assignSchedulerPasswordKey(settings: NoteTweetSettings): boolean {
	const { scheduling } = settings;
	if (PASSWORD_KEY.test(scheduling.passwordKey)) return false;
	scheduling.passwordKey = randomId();
	scheduling.legacyPassword = Boolean(scheduling.enabled || scheduling.url);
	return true;
}

/** Store this vault's scheduler password on this device. */
export function setSchedulerPassword(
	app: App,
	settings: NoteTweetSettings,
	password: string,
): void {
	setSecret(app, schedulerPasswordSecretId(settings.scheduling.passwordKey), password);
	app.saveLocalStorage(passwordSetHere(settings), true);
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
	settings: NoteTweetSettings,
): string {
	const data = settings as unknown as LegacyCredentialData;
	const stored = getSecret(
		app,
		schedulerPasswordSecretId(settings.scheduling.passwordKey),
	);
	if (stored) return stored;
	// Once a password is set for this vault on this device, even an empty one,
	// the older sources no longer apply.
	if (app.loadLocalStorage(passwordSetHere(settings))) return "";
	// A pre-0.6 plaintext password belongs to this vault, so it outranks the
	// shared secret, which may have been saved by another vault.
	if (!data.secureMode && data.scheduling?.password) {
		return data.scheduling.password;
	}
	// Secrets stay on their device, so each device reads its own old password.
	if (settings.scheduling.legacyPassword) {
		return getSecret(app, LEGACY_SCHEDULER_PASSWORD_ID);
	}
	return "";
}
