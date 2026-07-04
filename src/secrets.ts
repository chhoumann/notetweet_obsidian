import type { App } from "obsidian";
import { log } from "./log";

/**
 * Stable SecretStorage keys owned by this plugin. Obsidian requires secret ids
 * to be lowercase alphanumeric with optional dashes.
 */
export const SECRET_IDS = {
	apiKey: "notetweet-api-key",
	apiSecret: "notetweet-api-secret",
	accessToken: "notetweet-access-token",
	accessTokenSecret: "notetweet-access-token-secret",
	schedulerPassword: "notetweet-scheduler-password",
} as const;

export type SecretId = (typeof SECRET_IDS)[keyof typeof SECRET_IDS];

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
	} catch (error) {
		log.message(`Failed to read secret "${id}": ${error}`);
		return "";
	}
}

export function setSecret(app: App, id: SecretId, value: string): void {
	app.secretStorage?.setSecret(id, value);
}

export function getTwitterCredentials(app: App): TwitterCredentials {
	return {
		apiKey: getSecret(app, SECRET_IDS.apiKey),
		apiSecret: getSecret(app, SECRET_IDS.apiSecret),
		accessToken: getSecret(app, SECRET_IDS.accessToken),
		accessTokenSecret: getSecret(app, SECRET_IDS.accessTokenSecret),
	};
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
