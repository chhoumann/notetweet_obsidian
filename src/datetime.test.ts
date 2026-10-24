import {
	formatDateTime,
	fromDateTimeInput,
	nextFullHour,
	toDateTimeInput,
} from "./datetime";

// Built from local Date parts so the expectations are timezone-independent.
const local = (...parts: [number, number, number, number, number]) =>
	new Date(...parts).getTime();

describe("formatDateTime", () => {
	it("formats a local timestamp as zero-padded DD-MM-YYYY HH:mm", () => {
		expect(formatDateTime(local(2026, 0, 5, 9, 7))).toBe("05-01-2026 09:07");
	});
});

describe("datetime-local input values", () => {
	it("round-trips a local time through the input format", () => {
		const ts = local(2026, 11, 31, 23, 5);

		expect(toDateTimeInput(ts)).toBe("2026-12-31T23:05");
		expect(fromDateTimeInput("2026-12-31T23:05")).toBe(ts);
	});

	it("treats a cleared picker as no time", () => {
		expect(fromDateTimeInput("")).toBeNull();
	});
});

describe("nextFullHour", () => {
	it("rounds up to the start of the next hour, across midnight", () => {
		expect(nextFullHour(local(2026, 9, 24, 23, 6))).toBe(local(2026, 9, 25, 0, 0));
	});
});
