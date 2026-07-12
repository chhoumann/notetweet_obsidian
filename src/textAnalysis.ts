import extractUrlsWithIndices from "twitter-text/dist/esm/extractUrlsWithIndices.js";
import parseTweet from "twitter-text/dist/esm/parseTweet.js";

// Deep ESM imports are deliberate: twitter-text's default export eagerly pulls
// every autolinking API into the Obsidian bundle. The dependency is pinned so
// this narrow official surface cannot drift underneath us.

export interface TextBoundary {
	/** UTF-16 index immediately after this indivisible URL or grapheme. */
	index: number;
	/** X-weighted length from the beginning of the normalized text. */
	weightedLength: number;
}

export interface TweetTextAnalysis {
	/** NFC text, matching the normalization X applies before counting. */
	normalizedText: string;
	/** X-weighted length, including transformed URLs and emoji sequences. */
	weightedLength: number;
	/** Whether twitter-text considers the normalized text a valid 280-char post. */
	valid: boolean;
	/** Safe split positions that never bisect a URL or Unicode grapheme. */
	boundaries: TextBoundary[];
}

const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });

/**
 * Analyze post text with X's official twitter-text rules. This is the sole
 * counting boundary used by the composer and splitter.
 */
export function analyzeTweetText(text: string): TweetTextAnalysis {
	const normalizedText = text.normalize("NFC");
	const parsed = parseTweet(normalizedText);
	const urls = extractUrlsWithIndices(normalizedText);
	const urlAt = new Map(urls.map((url) => [url.indices[0], url]));
	const boundaries: TextBoundary[] = [];
	let weightedLength = 0;
	let skipUntil = 0;

	for (const part of segmenter.segment(normalizedText)) {
		if (part.index < skipUntil) continue;

		const url = urlAt.get(part.index);
		if (url) {
			weightedLength += 23;
			skipUntil = url.indices[1];
			boundaries.push({ index: skipUntil, weightedLength });
			continue;
		}

		weightedLength += parseTweet(part.segment).weightedLength;
		boundaries.push({
			index: part.index + part.segment.length,
			weightedLength,
		});
	}

	return {
		normalizedText,
		weightedLength: parsed.weightedLength,
		valid: parsed.valid,
		boundaries,
	};
}
