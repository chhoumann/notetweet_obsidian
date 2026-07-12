declare module "twitter-text/dist/esm/parseTweet.js" {
	export interface ParsedTweet {
		weightedLength: number;
		valid: boolean;
		permillage: number;
		validRangeStart: number;
		validRangeEnd: number;
		displayRangeStart: number;
		displayRangeEnd: number;
	}

	export default function parseTweet(text?: string): ParsedTweet;
}

declare module "twitter-text/dist/esm/extractUrlsWithIndices.js" {
	export interface TwitterTextUrl {
		url: string;
		indices: [number, number];
	}

	export default function extractUrlsWithIndices(
		text: string,
	): TwitterTextUrl[];
}
