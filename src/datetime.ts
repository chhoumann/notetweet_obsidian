const pad = (value: number) => String(value).padStart(2, "0");

/** Format a timestamp as `DD-MM-YYYY HH:mm` in local time. */
export function formatDateTime(timestamp: number): string {
	const date = new Date(timestamp);
	return (
		`${pad(date.getDate())}-${pad(date.getMonth() + 1)}-${date.getFullYear()} ` +
		`${pad(date.getHours())}:${pad(date.getMinutes())}`
	);
}

/** A timestamp as a `datetime-local` input value (`YYYY-MM-DDTHH:mm`, local). */
export function toDateTimeInput(timestamp: number): string {
	const date = new Date(timestamp);
	return (
		`${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
		`T${pad(date.getHours())}:${pad(date.getMinutes())}`
	);
}

/**
 * Parse a `datetime-local` input value as local time. `null` when empty or
 * when the time doesn't exist locally, such as in a daylight-saving gap.
 */
export function fromDateTimeInput(value: string): number | null {
	const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(value);
	if (!match) return null;
	const [, year, month, day, hour, minute] = match.map(Number);
	const timestamp = new Date(year, month - 1, day, hour, minute).getTime();
	return toDateTimeInput(timestamp) === match[0] ? timestamp : null;
}

/** The start of the next full hour after `now`. */
export function nextFullHour(now: number): number {
	const date = new Date(now);
	date.setHours(date.getHours() + 1, 0, 0, 0);
	return date.getTime();
}
