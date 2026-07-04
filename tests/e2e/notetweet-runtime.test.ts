import { describe, expect, test } from "vitest";
import {
	createNoteTweetE2EHarness,
	evalJsonAsync,
	PLUGIN_ID,
	WAIT_OPTS,
} from "./harness";

const getContext = createNoteTweetE2EHarness("notetweet-runtime");

describe("NoteTweet runtime", () => {
	test("registers its three production commands and omits the dev reload command", async () => {
		const { obsidian } = getContext();

		const commandIds = await obsidian.dev.evalJson<string[]>(
			`Object.keys(app.commands?.commands ?? {})
				.filter((id) => id.startsWith(${JSON.stringify(`${PLUGIN_ID}:`)}))
				.sort()`,
		);

		expect(commandIds).toContain(`${PLUGIN_ID}:post-tweet`);
		expect(commandIds).toContain(`${PLUGIN_ID}:post-selected-as-tweet`);
		expect(commandIds).toContain(`${PLUGIN_ID}:post-file-as-thread`);
		// The old dev-only "Reload (dev)" command was removed entirely: the
		// directory review flags self-disable/re-enable as a malware pattern,
		// so no build may ever register it again.
		expect(commandIds).not.toContain(`${PLUGIN_ID}:reload`);
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

	test("exposes SecretStorage that round-trips a secret on the live runtime", async () => {
		const { obsidian } = getContext();

		const probeId = "notetweet-e2e-probe";
		const probeValue = "notetweet-e2e-secret-value";

		const result = await evalJsonAsync<{
			hasSetSecret: boolean;
			hasGetSecret: boolean;
			hasListSecrets: boolean;
			readBack: string | null;
			listedAfterSet: boolean;
		}>(
			obsidian,
			`
			(async () => {
				const storage = app.secretStorage;
				const probeId = ${JSON.stringify(probeId)};
				const probeValue = ${JSON.stringify(probeValue)};

				const hasSetSecret = typeof storage?.setSecret === "function";
				const hasGetSecret = typeof storage?.getSecret === "function";
				const hasListSecrets = typeof storage?.listSecrets === "function";

				await storage.setSecret(probeId, probeValue);
				const readBack = await storage.getSecret(probeId);
				const listedAfterSet = (await storage.listSecrets()).includes(probeId);

				// Blank the throwaway secret so no per-run state leaks into the vault.
				await storage.setSecret(probeId, "");

				return { hasSetSecret, hasGetSecret, hasListSecrets, readBack, listedAfterSet };
			})()
			`,
		);

		expect(result.hasSetSecret).toBe(true);
		expect(result.hasGetSecret).toBe(true);
		expect(result.hasListSecrets).toBe(true);
		// The value written under SecretStorage must survive a real read-back:
		// this is the core assumption the credential modernization relies on.
		expect(result.readBack).toBe(probeValue);
		expect(result.listedAfterSet).toBe(true);
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

	test("opens the compose-tweet modal for the post-tweet command and closes it", async () => {
		const { obsidian } = getContext();

		const modalSelector = ".postTweetModal textarea.tweetArea";

		// Fire the user-facing command; its callback opens ComposeTweetModal, whose
		// content root carries the postTweetModal class and a tweetArea textarea.
		await obsidian.dev.evalJson<boolean>(
			`app.commands.executeCommandById(${JSON.stringify(`${PLUGIN_ID}:post-tweet`)})`,
		);

		await obsidian.waitFor(
			() =>
				obsidian.dev.evalJson<boolean>(
					`Boolean(document.querySelector(${JSON.stringify(modalSelector)}))`,
				),
			{ ...WAIT_OPTS, message: "Compose tweet modal did not open." },
		);

		const hasTextarea = await obsidian.dev.evalJson<boolean>(
			`Boolean(document.querySelector(${JSON.stringify(modalSelector)}))`,
		);
		expect(hasTextarea).toBe(true);

		// Dismiss the composer the way a user does: Escape, which an Obsidian
		// modal closes on via its scope. (`app.workspace.activeModal` is not a
		// real API - it silently no-ops - so an Escape keydown is the reliable,
		// user-faithful dismissal.)
		await obsidian.dev.evalJson<boolean>(
			`(() => {
				const target = document.activeElement ?? document.body;
				target.dispatchEvent(
					new KeyboardEvent("keydown", {
						key: "Escape",
						code: "Escape",
						keyCode: 27,
						which: 27,
						bubbles: true,
					}),
				);
				return true;
			})()`,
		);

		await obsidian.waitFor(
			() =>
				obsidian.dev.evalJson<boolean>(
					`document.querySelector(".postTweetModal") === null`,
				),
			{ ...WAIT_OPTS, message: "Compose tweet modal did not close." },
		);

		const closed = await obsidian.dev.evalJson<boolean>(
			`document.querySelector(".postTweetModal") === null`,
		);
		expect(closed).toBe(true);
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

	test("splits a post into two on a triple line break", async () => {
		const { obsidian } = getContext();
		const areaSelector = ".postTweetModal textarea.tweetArea";

		// Start from a clean modal surface so the field count is deterministic
		// even when the E2E instance is reused across runs. Dismiss any lingering
		// composer with Escape (which closes it properly and unregisters its
		// scope) rather than tearing DOM nodes out from under Obsidian.
		await obsidian.dev.evalJson<boolean>(
			`(() => {
				for (let i = 0; i < 10 && document.querySelector(".postTweetModal"); i++) {
					(document.activeElement ?? document.body).dispatchEvent(
						new KeyboardEvent("keydown", { key: "Escape", code: "Escape", keyCode: 27, which: 27, bubbles: true }),
					);
				}
				return document.querySelector(".postTweetModal") === null;
			})()`,
		);

		await obsidian.dev.evalJson<boolean>(
			`app.commands.executeCommandById(${JSON.stringify(`${PLUGIN_ID}:post-tweet`)})`,
		);
		await obsidian.waitFor(
			() =>
				obsidian.dev.evalJson<boolean>(
					`Boolean(document.querySelector(${JSON.stringify(areaSelector)}))`,
				),
			{ ...WAIT_OPTS, message: "Compose post modal did not open." },
		);

		// Typing three consecutive newlines starts a new post: the head stays in
		// the current field and the tail moves into a fresh one below it.
		const values = await obsidian.dev.evalJson<string[]>(
			`(() => {
				const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
				const first = document.querySelector(${JSON.stringify(areaSelector)});
				setter.call(first, "First post\\n\\n\\nSecond post");
				first.dispatchEvent(new Event("input", { bubbles: true }));
				return Array.from(document.querySelectorAll(${JSON.stringify(areaSelector)})).map((el) => el.value);
			})()`,
		);
		expect(values).toEqual(["First post", "Second post"]);

		await obsidian.dev.evalJson<boolean>(
			`(() => { (document.activeElement ?? document.body).dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", code: "Escape", keyCode: 27, which: 27, bubbles: true })); return true; })()`,
		);
		await obsidian.waitFor(
			() =>
				obsidian.dev.evalJson<boolean>(
					`document.querySelector(".postTweetModal") === null`,
				),
			{ ...WAIT_OPTS, message: "Compose post modal did not close." },
		);
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

	test("attaches images from the vault picker and from a paste", async () => {
		const { obsidian } = getContext();
		const imgSelector = ".postTweetModal .nt-attachment img";
		// 2x2 red PNG.
		const png =
			"iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAAEklEQVR4nGP8z8Dwn4EIwDiqEAAlHwMBmi5+VAAAAABJRU5ErkJggg==";

		// Dismiss any lingering modal, then seed one known image in the vault.
		await obsidian.dev.evalJson<boolean>(
			`(() => { for (let i=0;i<12 && document.querySelector(".modal-container");i++){ (document.activeElement ?? document.body).dispatchEvent(new KeyboardEvent("keydown",{key:"Escape",code:"Escape",keyCode:27,which:27,bubbles:true})); } return true; })()`,
		);
		await evalJsonAsync<boolean>(
			obsidian,
			`(async () => {
				const bin = atob(${JSON.stringify(png)}); const bytes = new Uint8Array(bin.length);
				for (let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
				const existing = app.vault.getAbstractFileByPath("nt-e2e-temp.png");
				if (existing) await app.vault.delete(existing);
				await app.vault.createBinary("nt-e2e-temp.png", bytes.buffer);
				return true;
			})()`,
		);

		try {
			await obsidian.dev.evalJson<boolean>(
				`app.commands.executeCommandById(${JSON.stringify(`${PLUGIN_ID}:post-tweet`)})`,
			);
			await obsidian.waitFor(
				() =>
					obsidian.dev.evalJson<boolean>(
						`Boolean(document.querySelector(".postTweetModal textarea.tweetArea"))`,
					),
				{ ...WAIT_OPTS, message: "Compose post modal did not open." },
			);

			// Attach via the vault picker: open it, choose the seeded image.
			await obsidian.dev.evalJson<boolean>(
				`(() => { document.querySelector('.postTweetModal [aria-label="Attach image"]').click(); return true; })()`,
			);
			await obsidian.waitFor(
				() =>
					obsidian.dev.evalJson<boolean>(
						`Boolean(document.querySelector(".suggestion-item"))`,
					),
				{ ...WAIT_OPTS, message: "Image picker did not open." },
			);
			await obsidian.dev.evalJson<boolean>(
				`(() => {
					const items = Array.from(document.querySelectorAll(".suggestion-item"));
					const target = items.find((el) => el.textContent.includes("nt-e2e-temp.png"));
					(target ?? items[0]).dispatchEvent(new MouseEvent("click", { bubbles: true }));
					return true;
				})()`,
			);
			await obsidian.waitFor(
				() =>
					obsidian.dev.evalJson<boolean>(
						`document.querySelectorAll(${JSON.stringify(imgSelector)}).length === 1`,
					),
				{ ...WAIT_OPTS, message: "Picker attachment did not render." },
			);

			// Attach by pasting an image: a synthetic paste carrying an image File
			// is saved to the vault and attached, taking the count to two.
			await obsidian.dev.evalJson<boolean>(
				`(() => {
					const bin = atob(${JSON.stringify(png)}); const bytes = new Uint8Array(bin.length);
					for (let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
					const dt = new DataTransfer();
					dt.items.add(new File([bytes], "clip.png", { type: "image/png" }));
					const ta = document.querySelector(".postTweetModal textarea.tweetArea");
					ta.focus();
					ta.dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }));
					return true;
				})()`,
			);
			await obsidian.waitFor(
				() =>
					obsidian.dev.evalJson<boolean>(
						`document.querySelectorAll(${JSON.stringify(imgSelector)}).length === 2`,
					),
				{ ...WAIT_OPTS, message: "Pasted attachment did not render." },
			);

			const total = await obsidian.dev.evalJson<number>(
				`document.querySelectorAll(${JSON.stringify(imgSelector)}).length`,
			);
			expect(total).toBe(2);
		} finally {
			// Close the composer and remove the seeded + pasted images from the vault.
			await obsidian.dev.evalJson<boolean>(
				`(() => { for (let i=0;i<12 && document.querySelector(".modal-container");i++){ (document.activeElement ?? document.body).dispatchEvent(new KeyboardEvent("keydown",{key:"Escape",code:"Escape",keyCode:27,which:27,bubbles:true})); } return true; })()`,
			);
			await evalJsonAsync<boolean>(
				obsidian,
				`(async () => {
					for (const file of app.vault.getFiles()) {
						if (file.path === "nt-e2e-temp.png" || file.name.startsWith("Pasted image ")) {
							await app.vault.delete(file);
						}
					}
					return true;
				})()`,
			);
		}
	});
});
