import { Notice } from "obsidian";

const PREFIX = "NoteTweet";

const ERROR_NOTICE_MS = 10_000;

/**
 * Minimal logging surface for the plugin. Everything reaches the user as a
 * `Notice`; errors stay on screen longer so they can be read and reported.
 * Nothing is written to the developer console, per Obsidian's plugin
 * guidelines.
 */
export const log = {
	error(message: string): void {
		new Notice(`${PREFIX}: ${message}`, ERROR_NOTICE_MS);
	},
	warning(message: string): void {
		new Notice(`${PREFIX}: ${message}`);
	},
};
