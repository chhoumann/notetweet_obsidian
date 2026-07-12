import { deferred } from "./deferred";

describe("deferred", () => {
	it("resolves with a value", async () => {
		const { promise, resolve } = deferred<string>();

		resolve("ready");

		await expect(promise).resolves.toBe("ready");
	});

	it("resolves void promises", async () => {
		const { promise, resolve } = deferred<void>();

		resolve();

		await expect(promise).resolves.toBeUndefined();
	});
});
