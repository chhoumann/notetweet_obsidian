import { analyzeTweetText, type TextBoundary } from "./textAnalysis";

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
 * Split text into posts within X's weighted limit. Sentence and whitespace
 * boundaries are preferred, while official URL entities and Unicode graphemes
 * remain indivisible. Text is normalized to NFC, matching X's counting rules.
 */
export function splitIntoTweets(
	text: string,
	maxLength: number = MAX_TWEET_LENGTH,
): string[] {
	if (!Number.isFinite(maxLength) || maxLength <= 0) {
		throw new RangeError("Tweet length must be a positive number.");
	}

	const analysis = analyzeTweetText(text);
	const { normalizedText, boundaries } = analysis;
	if (analysis.weightedLength <= maxLength) {
		return normalizedText.trim().length > 0 ? [normalizedText] : [];
	}

	const chunks: string[] = [];
	let startIndex = 0;
	let startBoundary = 0;
	let consumedWeight = 0;

	while (startBoundary < boundaries.length) {
		const limit = findLimit(boundaries, startBoundary, consumedWeight, maxLength);
		if (limit === startBoundary) {
			throw new Error("A single URL or grapheme exceeds the tweet length limit.");
		}

		const endBoundary = chooseBreak(
			normalizedText,
			boundaries,
			startBoundary,
			limit,
			startIndex,
		);
		const endIndex = boundaries[endBoundary - 1].index;
		const chunk = normalizedText.slice(startIndex, endIndex).trim();
		if (chunk.length > 0) chunks.push(chunk);

		consumedWeight = boundaries[endBoundary - 1].weightedLength;
		startBoundary = endBoundary;
		startIndex = endIndex;
	}

	return chunks;
}

function findLimit(
	boundaries: TextBoundary[],
	start: number,
	consumedWeight: number,
	maxLength: number,
): number {
	let end = start;
	while (
		end < boundaries.length &&
		boundaries[end].weightedLength - consumedWeight <= maxLength
	) {
		end++;
	}
	return end;
}

function chooseBreak(
	text: string,
	boundaries: TextBoundary[],
	start: number,
	limit: number,
	startIndex: number,
): number {
	if (limit === boundaries.length) return limit;

	let sentenceBreak = -1;
	let whitespaceBreak = -1;
	for (let index = start; index < limit; index++) {
		const unitStart = index === start ? startIndex : boundaries[index - 1].index;
		const unit = text.slice(unitStart, boundaries[index].index);
		if (/^\s+$/u.test(unit)) whitespaceBreak = index + 1;
		if (/[.?!]$/u.test(unit) && index + 1 < limit) {
			const nextStart = boundaries[index].index;
			const next = text.slice(nextStart, boundaries[index + 1].index);
			if (/^\s+$/u.test(next)) sentenceBreak = index + 1;
		}
	}

	if (sentenceBreak > start) return sentenceBreak;
	return whitespaceBreak > start ? whitespaceBreak : limit;
}
