import type { App } from "obsidian";

/**
 * Stable SecretStorage keys owned by this plugin. Obsidian requires secret ids
 * to be lowercase alphanumeric with optional dashes.
 */
export const LEGACY_TWITTER_SECRET_IDS = {
	apiKey: "notetweet-api-key",
	apiSecret: "notetweet-api-secret",
	accessToken: "notetweet-access-token",
	accessTokenSecret: "notetweet-access-token-secret",
} as const;

export const SECRET_IDS = {
	schedulerPassword: "notetweet-scheduler-password",
} as const;

export type SecretId = string;

export interface TwitterCredentials {
	apiKey: string;
	apiSecret: string;
	accessToken: string;
	accessTokenSecret: string;
}

/** True when this Obsidian build exposes the SecretStorage API (>= 1.11.4). */
export function hasSecretStorage(app: App): boolean {
	const storage = app.secretStorage;
	return (
		!!storage &&
		typeof storage.getSecret === "function" &&
		typeof storage.setSecret === "function"
	);
}

export function getSecret(app: App, id: SecretId): string {
	try {
		return app.secretStorage?.getSecret(id) ?? "";
	} catch {
		return "";
	}
}

export function setSecret(app: App, id: SecretId, value: string): void {
	app.secretStorage?.setSecret(id, value);
}

const ACCOUNT_SECRET_SUFFIX = {
	apiKey: "api-key",
	apiSecret: "api-secret",
	accessToken: "access-token",
	accessTokenSecret: "access-token-secret",
} as const satisfies Record<keyof TwitterCredentials, string>;
const TWITTER_CREDENTIAL_FIELDS = Object.keys(
	ACCOUNT_SECRET_SUFFIX,
) as (keyof TwitterCredentials)[];

export function accountSecretId(
	accountId: string,
	field: keyof TwitterCredentials,
): string {
	return `notetweet-account-${accountId}-${ACCOUNT_SECRET_SUFFIX[field]}`;
}

export function getAccountCredentials(
	app: App,
	accountId: string,
): TwitterCredentials {
	return {
		apiKey: getSecret(app, accountSecretId(accountId, "apiKey")),
		apiSecret: getSecret(app, accountSecretId(accountId, "apiSecret")),
		accessToken: getSecret(app, accountSecretId(accountId, "accessToken")),
		accessTokenSecret: getSecret(
			app,
			accountSecretId(accountId, "accessTokenSecret"),
		),
	};
}

export function setAccountCredentials(
	app: App,
	accountId: string,
	credentials: TwitterCredentials,
): void {
	for (const field of TWITTER_CREDENTIAL_FIELDS) {
		setSecret(app, accountSecretId(accountId, field), credentials[field]);
	}
}

export function clearAccountCredentials(app: App, accountId: string): void {
	setAccountCredentials(app, accountId, {
		apiKey: "",
		apiSecret: "",
		accessToken: "",
		accessTokenSecret: "",
	});
}

/** All four Twitter credentials are present. Used by several connect paths. */
export function hasCompleteCredentials(credentials: TwitterCredentials): boolean {
	return Boolean(
		credentials.apiKey &&
			credentials.apiSecret &&
			credentials.accessToken &&
			credentials.accessTokenSecret,
	);
}
