import { formatDateTime } from "./datetime";

describe("formatDateTime", () => {
	it("formats a local timestamp as zero-padded DD-MM-YYYY HH:mm", () => {
		// Built from local Date parts so the expectation is timezone-independent.
		const ts = new Date(2026, 0, 5, 9, 7).getTime();

		expect(formatDateTime(ts)).toBe("05-01-2026 09:07");
	});
});
