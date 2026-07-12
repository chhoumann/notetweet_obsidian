import { parseThread, splitIntoTweets } from "./tweet";

describe("parseThread", () => {
	it("parses the exact issue #23 Markdown and its whitespace separator", () => {
		const text = [
			"THREAD START",
			"When one of the horsemen entered and saw that Nero was dying, he attempted to stop the bleeding, but efforts to save Nero's life were unsuccessful. Nero's final words were \"Too late! This is fidelity!\"",
			"",
			"[Nero](https://en.wikipedia.org/wiki/Nero?wprov=sfti1)",
			"",
			"--- ",
			"a stark contrast to the final words of his ancestor Augustus, but Latin makes everything seem like a great play",
			"THREAD END",
		].join("\n");

		expect(parseThread(text)).toEqual([
			[
				"When one of the horsemen entered and saw that Nero was dying, he attempted to stop the bleeding, but efforts to save Nero's life were unsuccessful. Nero's final words were \"Too late! This is fidelity!\"",
				"",
				"[Nero](https://en.wikipedia.org/wiki/Nero?wprov=sfti1)",
			].join("\n"),
			"a stark contrast to the final words of his ancestor Augustus, but Latin makes everything seem like a great play",
		]);
	});

	it("accepts CRLF newlines", () => {
		const text = [
			"THREAD START",
			"first tweet",
			"---",
			"second tweet",
			"THREAD END",
		].join("\r\n");

		expect(parseThread(text)).toEqual(["first tweet", "second tweet"]);
	});

	it("recognizes markers with surrounding whitespace", () => {
		const text = [
			"  THREAD START\t",
			"first tweet",
			"\tTHREAD END  ",
		].join("\n");

		expect(parseThread(text)).toEqual(["first tweet"]);
	});

	it("recognizes a separator with surrounding whitespace", () => {
		const text = [
			"THREAD START",
			"first tweet",
			" \t---  ",
			"second tweet",
			"THREAD END",
		].join("\n");

		expect(parseThread(text)).toEqual(["first tweet", "second tweet"]);
	});

	it("removes structural blank lines without changing tweet body lines", () => {
		const text = [
			"THREAD START",
			"",
			"  indented first line  ",
			"",
			"second paragraph",
			"",
			"---",
			"",
			"second tweet",
			"",
			"THREAD END",
		].join("\n");

		expect(parseThread(text)).toEqual([
			"  indented first line  \n\nsecond paragraph",
			"second tweet",
		]);
	});

	it("ignores marker-like lines in surrounding fenced code", () => {
		const text = [
			"```text",
			"THREAD START",
			"not a thread",
			"THREAD END",
			"```",
			"",
			"THREAD START",
			"actual first tweet",
			"---",
			"```text",
			"---",
			"THREAD END",
			"```",
			"actual second tweet",
			"THREAD END",
		].join("\n");

		expect(parseThread(text)).toEqual([
			"actual first tweet",
			"```text\n---\nTHREAD END\n```\nactual second tweet",
		]);
	});

	it("throws when THREAD START is missing", () => {
		const text = ["some tweet", "THREAD END"].join("\n");

		expect(() => parseThread(text)).toThrow(/missing a THREAD START marker/);
	});

	it("throws when THREAD END is missing", () => {
		const text = ["THREAD START", "some tweet"].join("\n");

		expect(() => parseThread(text)).toThrow(/missing a THREAD END marker/);
	});

	it("throws when the markers are reversed", () => {
		const text = ["THREAD END", "some tweet", "THREAD START"].join("\n");

		expect(() => parseThread(text)).toThrow(/appears before THREAD START/);
	});

	it("throws when the thread body is empty", () => {
		const text = ["THREAD START", "THREAD END"].join("\n");

		expect(() => parseThread(text)).toThrow(/thread is empty/i);
	});

	it.each([
		["first", ["THREAD START", "---", "second", "THREAD END"]],
		["middle", ["THREAD START", "first", "---", "", "---", "third", "THREAD END"]],
		["last", ["THREAD START", "first", "---", "THREAD END"]],
	])("throws when the %s tweet is empty", (_position, lines) => {
		expect(() => parseThread(lines.join("\n"))).toThrow(/Tweet \d+ is empty/);
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

		// The sentence split keeps the punctuation attached to each sentence.
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
