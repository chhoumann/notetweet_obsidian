import type { App } from "obsidian";
import {
	SECRET_IDS,
	getTwitterCredentials,
	hasCompleteCredentials,
	setSecret,
	type TwitterCredentials,
} from "./secrets";
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
	credentials: MigratableCredentials,
): void {
	if (credentials.apiKey) setSecret(app, SECRET_IDS.apiKey, credentials.apiKey);
	if (credentials.apiSecret)
		setSecret(app, SECRET_IDS.apiSecret, credentials.apiSecret);
	if (credentials.accessToken)
		setSecret(app, SECRET_IDS.accessToken, credentials.accessToken);
	if (credentials.accessTokenSecret)
		setSecret(app, SECRET_IDS.accessTokenSecret, credentials.accessTokenSecret);
	if (credentials.schedulerPassword)
		setSecret(app, SECRET_IDS.schedulerPassword, credentials.schedulerPassword);
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

/**
 * The credentials the plugin should connect with right now: SecretStorage when
 * populated, otherwise the legacy plaintext values so plaintext users keep
 * working until they migrate. Secure-mode (encrypted) values are never returned
 * here - those require the migration password first.
 */
export function resolveCredentials(
	app: App,
	data: LegacyCredentialData,
): TwitterCredentials {
	const stored = getTwitterCredentials(app);
	if (hasCompleteCredentials(stored)) return stored;

	if (legacyCredentialsPresent(data) && !legacyCredentialsEncrypted(data)) {
		const legacy = readLegacyCredentials(data);
		return {
			apiKey: legacy.apiKey,
			apiSecret: legacy.apiSecret,
			accessToken: legacy.accessToken,
			accessTokenSecret: legacy.accessTokenSecret,
		};
	}

	return stored;
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
