export const MAX_TWEET_LENGTH = 280;

export const THREAD_START = "THREAD START";
export const THREAD_END = "THREAD END";

/** A tweet stored by the self-hosted scheduler. `postat` matches the server field. */
export interface ScheduledTweet {
	id: string;
	content: string[];
	postat: number;
}

/**
 * Outcome of the compose modal. `content` holds one entry per tweet in the
 * thread. When `postAt` is set, the caller should schedule rather than post.
 */
export interface ComposeResult {
	content: string[];
	postAt?: number;
}

/**
 * Extract the tweets of a thread delimited by `THREAD START` / `THREAD END`,
 * split on a `---` line. Throws when the markers are missing or the thread is
 * empty.
 */
export function parseThread(text: string): string[] {
	const lines = text.split("\n");
	const startIndex = lines.indexOf(THREAD_START) + 1;
	const endIndex = lines.indexOf(THREAD_END);

	if (startIndex === 0 || endIndex === -1) {
		throw new Error("Failed to detect THREAD START or THREAD END");
	}

	const content = lines
		.slice(startIndex, endIndex)
		.join("\n")
		.split("\n---\n");

	if (content.length === 1 && content[0] === "") {
		throw new Error("Please write something in your thread.");
	}

	return content.map((tweet) => tweet.trim());
}

/**
 * Greedily pack newline-separated lines into chunks no longer than `maxLength`,
 * preserving the newline between packed lines. A single line that is itself too
 * long is split on sentence boundaries and re-packed recursively, falling back
 * to a hard word/character wrap for unbreakable text.
 */
export function splitIntoTweets(
	text: string,
	maxLength: number = MAX_TWEET_LENGTH,
): string[] {
	const chunks: string[] = [];

	for (const line of text.split("\n")) {
		if (line.length > maxLength) {
			const bySentence = line.split(/(?<=[.?!])\s/).join("\n");
			// A line with no sentence boundary won't shrink by re-splitting, so
			// fall back to a hard word/character wrap to guarantee progress.
			const pieces =
				bySentence === line
					? hardWrap(line, maxLength)
					: splitIntoTweets(bySentence, maxLength);
			chunks.push(...pieces);
			continue;
		}

		const last = chunks.length - 1;
		const combined = last < 0 ? line : `${chunks[last]}\n${line}`;
		if (last >= 0 && combined.length <= maxLength) {
			chunks[last] = combined;
		} else {
			chunks.push(line);
		}
	}

	return chunks.filter((chunk) => chunk.trim().length > 0);
}

/**
 * Break an unbreakable line into pieces no longer than `maxLength`, preferring
 * the last space inside the window and falling back to a hard cut when a single
 * word exceeds the limit.
 */
function hardWrap(text: string, maxLength: number): string[] {
	const pieces: string[] = [];
	let rest = text;

	while (rest.length > maxLength) {
		let cut = rest.lastIndexOf(" ", maxLength);
		if (cut <= 0) cut = maxLength;
		pieces.push(rest.slice(0, cut));
		rest = rest.slice(cut).replace(/^\s+/, "");
	}

	if (rest.length > 0) pieces.push(rest);
	return pieces;
}
