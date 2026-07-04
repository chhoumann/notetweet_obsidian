import type { App } from "obsidian";
import { InputPromptModal } from "./Modals/InputPromptModal";

interface NldParseResult {
	date: Date;
}
interface NldPlugin {
	parseDate(input: string): NldParseResult | null;
}
interface AppWithPlugins {
	plugins?: { plugins?: Record<string, unknown> };
}

/** Format a timestamp as `DD-MM-YYYY HH:mm` in local time. */
export function formatDateTime(timestamp: number): string {
	const date = new Date(timestamp);
	const pad = (value: number) => String(value).padStart(2, "0");
	return (
		`${pad(date.getDate())}-${pad(date.getMonth() + 1)}-${date.getFullYear()} ` +
		`${pad(date.getHours())}:${pad(date.getMinutes())}`
	);
}

/**
 * Prompt for a natural-language time and resolve it via the Natural Language
 * Dates plugin. Returns `null` when the user cancels; throws when NLD is
 * unavailable or the input cannot be parsed.
 */
export async function promptForDateTime(app: App): Promise<number | null> {
	const input = await InputPromptModal.prompt(app, "Schedule time", {
		placeholder: "today at 11:00",
	});
	if (input === null || input.trim() === "") return null;

	// Obsidian's plugin registry is not part of the public App type.
	const appWithPlugins = app as unknown as AppWithPlugins;
	const nld = appWithPlugins.plugins?.plugins?.["nldates-obsidian"] as
		| NldPlugin
		| undefined;
	if (!nld?.parseDate) {
		throw new Error(
			"The Natural Language Dates plugin is required to schedule tweets.",
		);
	}

	const parsed = nld.parseDate(input);
	if (!parsed?.date || Number.isNaN(parsed.date.getTime())) {
		throw new Error(`Could not understand the date "${input}".`);
	}
	return parsed.date.getTime();
}
