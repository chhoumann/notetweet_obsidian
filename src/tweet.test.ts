import { parseThread, splitIntoTweets } from "./tweet";

describe("parseThread", () => {
	it("returns each tweet in order, trimmed", () => {
		const text = [
			"THREAD START",
			"  first tweet  ",
			"---",
			"second tweet",
			"THREAD END",
		].join("\n");

		expect(parseThread(text)).toEqual(["first tweet", "second tweet"]);
	});

	it("throws when THREAD START is missing", () => {
		const text = ["some tweet", "THREAD END"].join("\n");

		expect(() => parseThread(text)).toThrow(/THREAD START or THREAD END/);
	});

	it("throws when THREAD END is missing", () => {
		const text = ["THREAD START", "some tweet"].join("\n");

		expect(() => parseThread(text)).toThrow(/THREAD START or THREAD END/);
	});

	it("throws when the thread body is empty", () => {
		const text = ["THREAD START", "THREAD END"].join("\n");

		expect(() => parseThread(text)).toThrow(/write something/);
	});
});

describe("splitIntoTweets", () => {
	it("returns a single chunk when the text is within the limit", () => {
		expect(splitIntoTweets("hello world", 280)).toEqual(["hello world"]);
	});

	it("packs multiple short lines greedily into as few chunks as possible", () => {
		const text = ["aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd"].join("\n");

		const chunks = splitIntoTweets(text, 20);

		// Greedy: four 8-char lines fit two-per-chunk, not one line per chunk.
		expect(chunks).toHaveLength(2);
		for (const chunk of chunks) {
			expect(chunk.length).toBeLessThanOrEqual(20);
		}
		// No characters are dropped or duplicated while packing (separators aside).
		expect(chunks.join("").replace(/\n/g, "")).toBe(
			"aaaaaaaabbbbbbbbccccccccdddddddd",
		);
	});

	it("splits a long line on sentence boundaries", () => {
		const text = "First sentence. Second sentence. Third sentence.";

		const chunks = splitIntoTweets(text, 20);

		// Lookbehind split keeps the punctuation attached to each sentence.
		expect(chunks).toEqual([
			"First sentence.",
			"Second sentence.",
			"Third sentence.",
		]);
		for (const chunk of chunks) {
			expect(chunk.length).toBeLessThanOrEqual(20);
		}
	});

	it("terminates on an unbreakable overlong line with no spaces or punctuation", () => {
		// Bug fix 1: a line with no space and no sentence break must not loop
		// forever - it is hard-wrapped into bounded pieces.
		const chunks = splitIntoTweets("a".repeat(50), 20);

		expect(chunks.length).toBeGreaterThan(1);
		for (const chunk of chunks) {
			expect(chunk.length).toBeLessThanOrEqual(20);
		}
		// No characters are dropped while wrapping.
		expect(chunks.join("")).toBe("a".repeat(50));
	});

	it("emits no empty leading chunk when the first line overflows", () => {
		// Bug fix 2: the placeholder chunk[0] left behind when the first line
		// overflows must be dropped, not returned as an empty tweet.
		const chunks = splitIntoTweets("a".repeat(50), 20);

		expect(chunks[0]).not.toBe("");
		for (const chunk of chunks) {
			expect(chunk.trim().length).toBeGreaterThan(0);
		}
	});

	it("wraps a long spaced line at word boundaries", () => {
		const words = ["word1", "word2", "word3", "word4", "word5", "word6"];

		const chunks = splitIntoTweets(words.join(" "), 12);

		for (const chunk of chunks) {
			expect(chunk.length).toBeLessThanOrEqual(12);
		}
		// Wrapping happens at spaces, so no word is split across chunks.
		expect(chunks.flatMap((chunk) => chunk.split(" "))).toEqual(words);
	});

	it("preserves the newline separator between packed lines in continuation chunks", () => {
		const text = ["11111", "22222", "33333", "44444", "55555", "66666"].join(
			"\n",
		);

		// Adjacent lines packed together keep their "\n" - they must not merge
		// into a single run like "3333344444".
		expect(splitIntoTweets(text, 14)).toEqual([
			"11111\n22222",
			"33333\n44444",
			"55555\n66666",
		]);
	});
});
