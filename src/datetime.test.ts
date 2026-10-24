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
	it("round-trips a local time through the zero-padded input format", () => {
		const ts = local(2026, 0, 5, 9, 7);

		expect(toDateTimeInput(ts)).toBe("2026-01-05T09:07");
		expect(fromDateTimeInput("2026-01-05T09:07")).toBe(ts);
	});

	it("treats a cleared picker as no time", () => {
		expect(fromDateTimeInput("")).toBeNull();
	});

	it("rejects a time that doesn't exist locally", () => {
		expect(fromDateTimeInput("2026-02-30T10:00")).toBeNull();
	});

	it("rejects a time skipped by daylight saving", () => {
		const zone = process.env.TZ;
		process.env.TZ = "Europe/Copenhagen";
		try {
			expect(fromDateTimeInput("2027-03-28T02:30")).toBeNull();
			expect(fromDateTimeInput("2027-03-28T03:30")).not.toBeNull();
		} finally {
			if (zone === undefined) delete process.env.TZ;
			else process.env.TZ = zone;
		}
	});
});

describe("nextFullHour", () => {
	it("rounds up to the start of the next hour, across midnight", () => {
		expect(nextFullHour(local(2026, 9, 24, 23, 6))).toBe(local(2026, 9, 25, 0, 0));
	});

	it("moves an exact hour on to the following one", () => {
		expect(nextFullHour(local(2026, 9, 24, 23, 0))).toBe(local(2026, 9, 25, 0, 0));
	});
});
