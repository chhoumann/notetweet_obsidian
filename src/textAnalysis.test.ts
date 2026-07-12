import { analyzeTweetText } from "./textAnalysis";

describe("analyzeTweetText", () => {
	it("matches X's documented weighted-count examples", () => {
		expect(analyzeTweetText("Hello, world! 👋").weightedLength).toBe(16);
		expect(analyzeTweetText("界").weightedLength).toBe(2);

		for (const emoji of ["👾", "🙋🏽", "👨‍🎤", "👨‍👩‍👧‍👦"]) {
			expect(analyzeTweetText(emoji).weightedLength).toBe(2);
		}
	});

	it("counts every valid URL as 23 regardless of source length", () => {
		expect(analyzeTweetText("https://example.com").weightedLength).toBe(23);
		expect(
			analyzeTweetText(`https://example.com/${"path/".repeat(100)}`)
				.weightedLength,
		).toBe(23);
	});

	it("normalizes canonically equivalent text before counting", () => {
		const composed = analyzeTweetText("café");
		const decomposed = analyzeTweetText("cafe\u0301");

		expect(composed.weightedLength).toBe(4);
		expect(decomposed.weightedLength).toBe(4);
		expect(decomposed.normalizedText).toBe(composed.normalizedText);
	});

	it("exposes only whole-URL and whole-grapheme split boundaries", () => {
		const family = "👨‍👩‍👧‍👦";
		const url = `https://example.com/${"a".repeat(200)}`;
		const analysis = analyzeTweetText(`A${family} ${url} Z`);
		const pieces = analysis.boundaries.map((boundary, index) => {
			const start = index === 0 ? 0 : analysis.boundaries[index - 1].index;
			return analysis.normalizedText.slice(start, boundary.index);
		});

		expect(pieces).toContain(family);
		expect(pieces).toContain(url);
		expect(analysis.boundaries.at(-1)?.weightedLength).toBe(
			analysis.weightedLength,
		);
	});
});
