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
 * split on a `---` line. Structural lines may have up to three leading spaces
 * plus trailing spaces or tabs, matching Markdown's non-code indentation, and
 * use LF or CRLF newlines. Marker-like lines inside fenced or indented code are
 * content, not structure.
 *
 * Blank lines directly beside a marker or separator are structural padding and
 * are removed. Every other body character is preserved. Missing, reversed, and
 * empty thread structures are rejected instead of producing malformed posts.
 */
export function parseThread(text: string): string[] {
	const lines = text.split(/\r\n|\n|\r/);
	const structuralLines = linesOutsideFencedCode(lines);
	const startIndex = lines.findIndex(
		(line, index) =>
			structuralLines[index] && isStructuralLine(line, THREAD_START),
	);
	const endIndex = lines.findIndex(
		(line, index) =>
			structuralLines[index] && isStructuralLine(line, THREAD_END),
	);

	if (startIndex === -1) {
		throw new Error("Thread is missing a THREAD START marker.");
	}
	if (endIndex === -1) {
		throw new Error("Thread is missing a THREAD END marker.");
	}
	if (endIndex < startIndex) {
		throw new Error("THREAD END appears before THREAD START.");
	}

	const segments: string[][] = [[]];
	for (let index = startIndex + 1; index < endIndex; index++) {
		const line = lines[index];
		if (structuralLines[index] && isStructuralLine(line, "---")) {
			segments.push([]);
		} else {
			segments[segments.length - 1].push(line);
		}
	}

	const normalized = segments.map(trimStructuralBlankLines);
	if (normalized.length === 1 && normalized[0].length === 0) {
		throw new Error("Thread is empty. Add content between the thread markers.");
	}

	return normalized.map((linesInTweet, index) => {
		if (linesInTweet.length === 0) {
			throw new Error(
				`Tweet ${index + 1} is empty. Add content between thread separators.`,
			);
		}
		return linesInTweet.join("\n");
	});
}

/** Match a whole structural line without reclassifying Markdown indented code. */
function isStructuralLine(line: string, structure: string): boolean {
	const leadingSpaces = /^ */.exec(line)?.[0].length ?? 0;
	if (leadingSpaces > 3) return false;
	return line.slice(leadingSpaces).replace(/[ \t]+$/, "") === structure;
}

type Fence = { character: "`" | "~"; length: number };

/** Mark lines whose Markdown position is outside a backtick or tilde fence. */
function linesOutsideFencedCode(lines: string[]): boolean[] {
	const outside: boolean[] = [];
	let fence: Fence | null = null;

	for (const line of lines) {
		outside.push(fence === null);
		if (fence) {
			if (closesFence(line, fence)) fence = null;
		} else {
			fence = opensFence(line);
		}
	}

	return outside;
}

function opensFence(line: string): Fence | null {
	const match = /^[ \t]{0,3}(`{3,}|~{3,})/.exec(line);
	if (!match) return null;
	return {
		character: match[1][0] as Fence["character"],
		length: match[1].length,
	};
}

function closesFence(line: string, fence: Fence): boolean {
	const match = /^[ \t]{0,3}(`{3,}|~{3,})[ \t]*$/.exec(line);
	return (
		match?.[1][0] === fence.character && match[1].length >= fence.length
	);
}

function trimStructuralBlankLines(lines: string[]): string[] {
	let start = 0;
	let end = lines.length;
	while (start < end && lines[start].trim() === "") start++;
	while (end > start && lines[end - 1].trim() === "") end--;
	return lines.slice(start, end);
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
			// `replace` instead of a lookbehind split: lookbehinds crash the
			// regex engine on iOS < 16.4, which Obsidian still supports.
			const bySentence = line.replace(/([.?!])\s/g, "$1\n");
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
