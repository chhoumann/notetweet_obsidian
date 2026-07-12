import { describe, expect, test } from "vitest";
import {
	createNoteTweetE2EHarness,
	PLUGIN_ID,
	RELOAD_OPTIONS,
	WAIT_OPTS,
	waitForNoteTweetReady,
} from "./harness";

const getContext = createNoteTweetE2EHarness("notetweet-runtime");

const ISSUE_23_THREAD = [
	"THREAD START",
	"When one of the horsemen entered and saw that Nero was dying, he attempted to stop the bleeding, but efforts to save Nero's life were unsuccessful. Nero's final words were \"Too late! This is fidelity!\"",
	"",
	"[Nero](https://en.wikipedia.org/wiki/Nero?wprov=sfti1)",
	"",
	"--- ",
	"a stark contrast to the final words of his ancestor Augustus, but Latin makes everything seem like a great play",
	"THREAD END",
].join("\n");

const INDENTED_CODE_THREAD = [
	"THREAD START",
	"first paragraph",
	"",
	"    THREAD END",
	"    ---",
	"content after indented code",
	"---",
	"second post",
	"THREAD END",
].join("\n");

describe("NoteTweet runtime", () => {
	test("passes the issue #23 file to X as two posts", async () => {
		const { obsidian, sandbox } = getContext();
		const notePath = sandbox.path("issue-23-thread.md");

		await sandbox.writeNote({
			path: "issue-23-thread.md",
			body: ISSUE_23_THREAD,
		});
		await obsidian.open({ path: notePath });
		await obsidian.waitForActiveFile(notePath);

		await obsidian.dev.evalJson<boolean>(
			`(() => {
				const plugin = app.plugins.plugins.${PLUGIN_ID};
				window.__notetweetE2ECapturedThread = null;
				window.__notetweetE2ECapturedAccount = null;
				plugin.settings.accounts = [{ id: "parser-account", name: "Parser account" }];
				plugin.settings.defaultAccountId = "parser-account";
				plugin.connectAccount = async (accountId) => ({
					isConnected: true,
					lastError: null,
					postThread: async (thread) => {
						window.__notetweetE2ECapturedAccount = accountId;
						window.__notetweetE2ECapturedThread = thread;
						return [];
					},
				});
				return true;
			})()`,
		);

		await obsidian.command(`${PLUGIN_ID}:post-file-as-thread`).run();
		await obsidian.waitFor(
			() =>
				obsidian.dev.evalJson<boolean>(
					"Array.isArray(window.__notetweetE2ECapturedThread)",
				),
			{
					...WAIT_OPTS,
					message: "Post file as thread did not reach the X posting boundary.",
			},
		);

		const thread = await obsidian.dev.evalJson<string[]>(
			"window.__notetweetE2ECapturedThread",
		);
		expect(thread).toEqual([
			[
				"When one of the horsemen entered and saw that Nero was dying, he attempted to stop the bleeding, but efforts to save Nero's life were unsuccessful. Nero's final words were \"Too late! This is fidelity!\"",
				"",
				"[Nero](https://en.wikipedia.org/wiki/Nero?wprov=sfti1)",
			].join("\n"),
			"a stark contrast to the final words of his ancestor Augustus, but Latin makes everything seem like a great play",
		]);
		expect(
			await obsidian.dev.evalJson<string>(
				"window.__notetweetE2ECapturedAccount",
			),
		).toBe("parser-account");
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

	test("preserves indented code that resembles thread structure", async () => {
		const { obsidian, sandbox } = getContext();
		const notePath = sandbox.path("indented-code-thread.md");

		await sandbox.writeNote({
			path: "indented-code-thread.md",
			body: INDENTED_CODE_THREAD,
		});
		await obsidian.open({ path: notePath });
		await obsidian.waitForActiveFile(notePath);

		await obsidian.dev.evalJson<boolean>(
			`(() => {
				const plugin = app.plugins.plugins.${PLUGIN_ID};
				window.__notetweetE2ECapturedThread = null;
				window.__notetweetE2ECapturedAccount = null;
				plugin.settings.accounts = [{ id: "parser-account", name: "Parser account" }];
				plugin.settings.defaultAccountId = "parser-account";
				plugin.connectAccount = async (accountId) => ({
					isConnected: true,
					lastError: null,
					postThread: async (thread) => {
						window.__notetweetE2ECapturedAccount = accountId;
						window.__notetweetE2ECapturedThread = thread;
						return [];
					},
				});
				return true;
			})()`,
		);

		await obsidian.command(`${PLUGIN_ID}:post-file-as-thread`).run();
		await obsidian.waitFor(
			() =>
				obsidian.dev.evalJson<boolean>(
					"Array.isArray(window.__notetweetE2ECapturedThread)",
				),
			{
					...WAIT_OPTS,
					message: "Indented-code thread did not reach the X posting boundary.",
			},
		);

		const thread = await obsidian.dev.evalJson<string[]>(
			"window.__notetweetE2ECapturedThread",
		);
		expect(thread).toEqual([
			[
				"first paragraph",
				"",
				"    THREAD END",
				"    ---",
				"content after indented code",
			].join("\n"),
			"second post",
		]);
		expect(
			await obsidian.dev.evalJson<string>(
				"window.__notetweetE2ECapturedAccount",
			),
		).toBe("parser-account");
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

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

		const result = await obsidian.dev.evalJsonAsync<{
			hasSetSecret: boolean;
			hasGetSecret: boolean;
			hasListSecrets: boolean;
			readBack: string | null;
			listedAfterSet: boolean;
		}>(
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

	test("uses X-weighted counts for composer validation, paste splitting, and Enter", async () => {
		const { obsidian } = getContext();
		const result = await obsidian.dev.evalJson<{
			states: Record<
				string,
				{ count: string; over: boolean; postDisabled: boolean }
			>;
			pasteLongUrlPrevented: boolean;
			pasteSplit: { prevented: boolean; values: string[] };
			enterCjkRows: number;
			enterLongUrlRows: number;
		}>(
			`(() => {
				const plugin = app.plugins.plugins.${PLUGIN_ID};
				plugin.settings.accounts = [{ id: "weighted-account", name: "Weighted account" }];
				plugin.settings.defaultAccountId = "weighted-account";
				const selector = ".postTweetModal textarea.tweetArea";
				const close = () => {
					for (let i = 0; i < 12 && document.querySelector(".postTweetModal"); i++) {
						(document.activeElement ?? document.body).dispatchEvent(
							new KeyboardEvent("keydown", { key: "Escape", code: "Escape", keyCode: 27, which: 27, bubbles: true }),
						);
					}
				};
				const open = () => {
					close();
					app.commands.executeCommandById(${JSON.stringify(`${PLUGIN_ID}:post-tweet`)});
					return document.querySelector(selector);
				};
				const setValue = (value) => {
					const area = document.querySelector(selector);
					const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
					setter.call(area, value);
					area.dispatchEvent(new Event("input", { bubbles: true }));
					return area;
				};
				const state = (value) => {
					open();
					setValue(value);
					const result = {
						count: document.querySelector(".postTweetModal .nt-count")?.textContent ?? "",
						over: document.querySelector(".postTweetModal .nt-post")?.classList.contains("is-over") ?? false,
						postDisabled: document.querySelector(".postTweetModal .nt-btn-cta")?.disabled ?? true,
					};
					close();
					return result;
				};
				const paste = (value) => {
					open();
					const area = document.querySelector(selector);
					const transfer = new DataTransfer();
					transfer.setData("text/plain", value);
					const event = new ClipboardEvent("paste", { clipboardData: transfer, bubbles: true, cancelable: true });
					area.dispatchEvent(event);
					const result = {
						prevented: event.defaultPrevented,
						values: Array.from(document.querySelectorAll(selector)).map((el) => el.value),
					};
					close();
					return result;
				};
				const enterRows = (value) => {
					open();
					const area = setValue(value);
					area.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true }));
					const rows = document.querySelectorAll(selector).length;
					close();
					return rows;
				};

				const longUrl = "https://example.com/" + "a".repeat(300);
				const pasteSplit = paste("a".repeat(258) + " " + longUrl + " tail");
				const result = {
					states: {
						longUrlAtLimit: state("a".repeat(256) + " " + longUrl),
						familyEmoji: state("👨‍👩‍👧‍👦".repeat(140)),
						cjkOver: state("界".repeat(141)),
						combiningAtLimit: state("e\\u0301".repeat(280)),
						latinAtLimit: state("a".repeat(280)),
					},
					pasteLongUrlPrevented: paste(longUrl).prevented,
					pasteSplit,
					enterCjkRows: enterRows("界".repeat(140)),
					enterLongUrlRows: enterRows(longUrl),
				};
				close();
				return result;
			})()`,
			{ timeoutMs: 60_000 },
		);

		expect(result.states.longUrlAtLimit).toEqual({
			count: "0",
			over: false,
			postDisabled: false,
		});
		expect(result.states.familyEmoji).toEqual({
			count: "0",
			over: false,
			postDisabled: false,
		});
		expect(result.states.cjkOver).toEqual({
			count: "-2",
			over: true,
			postDisabled: true,
		});
		expect(result.states.combiningAtLimit).toEqual({
			count: "0",
			over: false,
			postDisabled: false,
		});
		expect(result.states.latinAtLimit).toEqual({
			count: "0",
			over: false,
			postDisabled: false,
		});
		expect(result.pasteLongUrlPrevented).toBe(false);
		expect(result.pasteSplit.prevented).toBe(true);
		expect(result.pasteSplit.values).toHaveLength(2);
		expect(result.pasteSplit.values[1]).toContain(
			`https://example.com/${"a".repeat(300)}`,
		);
		expect(result.enterCjkRows).toBe(2);
		expect(result.enterLongUrlRows).toBe(1);
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

	test("posts through the account selected in the composer and explains scheduler identity", async () => {
		const { obsidian, plugin } = getContext();
		await plugin.updateDataAndReload(
			() => ({
				accounts: [
					{ id: "personal", name: "Personal" },
					{ id: "work", name: "Work" },
				],
				defaultAccountId: "personal",
				postTweetTag: "",
				autoSplitTweets: true,
				scheduling: { enabled: true, url: "https://scheduler.example" },
			}),
			RELOAD_OPTIONS,
		);
		await waitForNoteTweetReady(obsidian);

		try {
			await obsidian.dev.evalJson<boolean>(
				`(() => {
					const plugin = app.plugins.plugins.${PLUGIN_ID};
					window.__ntOriginalConnectAccount = plugin.connectAccount;
					window.__ntAccountProbe = null;
					plugin.connectAccount = async (accountId) => ({
						isConnected: true,
						lastError: null,
						postThread: async (content) => {
							window.__ntAccountProbe = { accountId, content };
							return [{ data: { id: "e2e-post", text: content[0] } }];
						},
						postTweet: async (text) => ({ data: { id: "e2e-post", text } }),
						deleteTweets: async () => true,
					});
					return app.commands.executeCommandById(${JSON.stringify(`${PLUGIN_ID}:post-tweet`)});
				})()`,
			);
			await obsidian.waitFor(
				() =>
					obsidian.dev.evalJson<boolean>(
						`Boolean(document.querySelector(".nt-account-select"))`,
					),
				{ ...WAIT_OPTS, message: "Composer account selector did not render." },
			);

			const composer = await obsidian.dev.evalJson<{
				initialAccount: string;
				schedulerCopy: string;
			}>(
				`(() => ({
					initialAccount: document.querySelector(".nt-account-select").value,
					schedulerCopy: document.querySelector(".nt-scheduler-identity")?.textContent ?? "",
				}))()`,
			);
			expect(composer.initialAccount).toBe("personal");
			expect(composer.schedulerCopy).toContain("scheduler's posting identity");

			await obsidian.dev.evalJson<boolean>(
				`(() => {
					const select = document.querySelector(".nt-account-select");
					select.value = "work";
					select.dispatchEvent(new Event("change", { bubbles: true }));
					const area = document.querySelector(".postTweetModal textarea.tweetArea");
					area.value = "Posted from work";
					area.dispatchEvent(new Event("input", { bubbles: true }));
					document.querySelector(".postTweetModal .nt-btn-cta").click();
					return true;
				})()`,
			);
			await obsidian.waitFor(
				() =>
					obsidian.dev.evalJson<boolean>(
						`Boolean(window.__ntAccountProbe && document.querySelector(".nt-posted-list"))`,
					),
				{ ...WAIT_OPTS, message: "Selected-account post did not complete." },
			);
			const posted = await obsidian.dev.evalJson<{
				accountId: string;
				content: string[];
			}>(`window.__ntAccountProbe`);
			expect(posted).toEqual({
				accountId: "work",
				content: ["Posted from work"],
			});
		} finally {
			await obsidian.dev.evalJson<boolean>(
				`(() => {
					const plugin = app.plugins.plugins.${PLUGIN_ID};
					if (window.__ntOriginalConnectAccount) plugin.connectAccount = window.__ntOriginalConnectAccount;
					for (const button of document.querySelectorAll("button")) {
						if (button.textContent === "Great!") button.click();
					}
					delete window.__ntOriginalConnectAccount;
					delete window.__ntAccountProbe;
					return true;
				})()`,
			);
		}
		expect(await obsidian.dev.runtimeErrors()).toEqual([]);
	});

	test("quick-post selection uses the configured default account", async () => {
		const { obsidian, plugin } = getContext();
		const notePath = "nt-e2e-default-account.md";
		await plugin.updateDataAndReload(
			() => ({
				accounts: [
					{ id: "personal", name: "Personal" },
					{ id: "work", name: "Work" },
				],
				defaultAccountId: "work",
				postTweetTag: "",
				autoSplitTweets: true,
				scheduling: { enabled: false, url: "" },
			}),
			RELOAD_OPTIONS,
		);

		try {
			await obsidian.dev.evalJsonAsync<boolean>(
				`(async () => {
					const existing = app.vault.getAbstractFileByPath(${JSON.stringify(notePath)});
					if (existing) await app.vault.delete(existing);
					const file = await app.vault.create(${JSON.stringify(notePath)}, "Quick post text");
					await app.workspace.getLeaf(false).openFile(file);
					const editor = app.workspace.activeLeaf.view.editor;
					editor.setSelection({ line: 0, ch: 0 }, { line: 0, ch: 10 });
					const plugin = app.plugins.plugins.${PLUGIN_ID};
					window.__ntOriginalConnectAccount = plugin.connectAccount;
					window.__ntQuickProbe = null;
					plugin.connectAccount = async (accountId) => ({
						isConnected: true,
						lastError: null,
						postTweet: async (text) => {
							window.__ntQuickProbe = { accountId, text };
							return { data: { id: "e2e-quick", text } };
						},
						postThread: async () => [],
						deleteTweets: async () => true,
					});
					app.commands.executeCommandById(${JSON.stringify(`${PLUGIN_ID}:post-selected-as-tweet`)});
					return true;
				})()`,
			);
			await obsidian.waitFor(
				() =>
					obsidian.dev.evalJson<boolean>(
						`Boolean(window.__ntQuickProbe && document.querySelector(".nt-posted-list"))`,
					),
				{ ...WAIT_OPTS, message: "Default-account quick post did not complete." },
			);
			const posted = await obsidian.dev.evalJson<{
				accountId: string;
				text: string;
			}>(`window.__ntQuickProbe`);
			expect(posted).toEqual({ accountId: "work", text: "Quick post" });
		} finally {
			await obsidian.dev.evalJsonAsync<boolean>(
				`(async () => {
					const plugin = app.plugins.plugins.${PLUGIN_ID};
					if (window.__ntOriginalConnectAccount) plugin.connectAccount = window.__ntOriginalConnectAccount;
					for (const button of document.querySelectorAll("button")) {
						if (button.textContent === "Great!") button.click();
					}
					const file = app.vault.getAbstractFileByPath(${JSON.stringify(notePath)});
					if (file) await app.vault.delete(file);
					delete window.__ntOriginalConnectAccount;
					delete window.__ntQuickProbe;
					return true;
				})()`,
			);
		}
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
		await obsidian.dev.evalJsonAsync<boolean>(
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
			await obsidian.dev.evalJsonAsync<boolean>(
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
