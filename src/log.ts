import { Notice } from "obsidian";

const PREFIX = "NoteTweet";

/**
 * Minimal logging surface for the plugin. Errors and warnings reach the user as
 * a `Notice`; everything is mirrored to the developer console. This replaces
 * the previous multi-class logger hierarchy, which added indirection without
 * value.
 */
export const log = {
	error(message: string): void {
		console.error(`${PREFIX}: ${message}`);
		new Notice(`${PREFIX}: ${message}`);
	},
	warning(message: string): void {
		console.warn(`${PREFIX}: ${message}`);
		new Notice(`${PREFIX}: ${message}`);
	},
	message(message: string): void {
		console.log(`${PREFIX}: ${message}`);
	},
};
