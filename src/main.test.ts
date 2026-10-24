import { App, Notice } from "obsidian";
import { ComposeTweetModal, type ComposeOptions } from "./Modals/ComposeTweetModal";
import NoteTweet from "./main";
import { ThreadPostError, type TwitterClient } from "./twitter";
import type { PostedTweet } from "./xApi";

vi.mock("./Modals/ComposeTweetModal", () => ({
	ComposeTweetModal: { compose: vi.fn() },
}));
const shownPosts = vi.hoisted(() => [] as PostedTweet[][]);
vi.mock("./Modals/TweetsPostedModal", () => ({
	TweetsPostedModal: class {
		constructor(_app: unknown, posts: PostedTweet[]) {
			shownPosts.push(posts);
		}
		open() {}
		waitForClose = new Promise(() => {});
	},
}));
vi.mock("./settingsTab", () => ({ NoteTweetSettingsTab: class {} }));

const compose = vi.mocked(ComposeTweetModal.compose);
const tweet = (id: string) => ({ data: { id, text: id } }) as PostedTweet;

/** Run the Post tweet command and return the `send` it hands the composer. */
async function composerSend(
	client: Partial<TwitterClient>,
): Promise<{ plugin: NoteTweet; send: NonNullable<ComposeOptions["send"]> }> {
	const app = Object.assign(new App(), {
		loadLocalStorage: () => null,
		saveLocalStorage: () => {},
	});
	const plugin = new NoteTweet(app, { id: "notetweet" } as never);
	const commands = new Map<string, () => void>();
	vi.spyOn(plugin, "addCommand").mockImplementation((command) => {
		if (command.callback) commands.set(command.id, command.callback);
		return command;
	});
	await plugin.onload();
	plugin.settings.accounts = [{ id: "acct", name: "Main" }];
	plugin.settings.defaultAccountId = "acct";
	vi.spyOn(plugin, "connectAccount").mockResolvedValue(client as TwitterClient);

	commands.get("post-tweet")?.();
	await vi.waitFor(() => expect(compose).toHaveBeenCalledOnce());
	const send = compose.mock.calls[0][1]?.send;
	if (!send) throw new Error("composer opened without send");
	return { plugin, send };
}

describe("Post tweet command", () => {
	beforeEach(() => {
		compose.mockReset().mockResolvedValue(null);
		Notice.reset();
		shownPosts.length = 0;
	});

	it("keeps the draft open when the account cannot connect", async () => {
		const { send } = await composerSend({ isConnected: false });

		await expect(send({ content: ["hi"], accountId: "acct" })).resolves.toBe(false);
		expect(Notice.messages.join("\n")).toContain("not connected");
	});

	it("keeps the draft open when the first tweet fails", async () => {
		const { send } = await composerSend({
			isConnected: true,
			postThread: vi.fn().mockRejectedValue(new ThreadPostError([], "429")),
		});

		await expect(send({ content: ["a", "b"], accountId: "acct" })).resolves.toBe(false);
		expect(Notice.messages.join("\n")).toContain("Failed to post tweet: 429");
	});

	it("keeps the draft open and offers undo when a thread fails part-way", async () => {
		const { send } = await composerSend({
			isConnected: true,
			postThread: vi.fn().mockRejectedValue(new ThreadPostError([tweet("1")], "429")),
		});

		await expect(send({ content: ["a", "b"], accountId: "acct" })).resolves.toBe(false);
		expect(shownPosts).toEqual([[tweet("1")]]);
		expect(Notice.messages.join("\n")).toContain("Posted 1 of 2, the rest failed: 429");
	});

	it("closes the composer and lists the thread once it is posted", async () => {
		const { send } = await composerSend({
			isConnected: true,
			postThread: vi.fn().mockResolvedValue([tweet("1"), tweet("2")]),
		});

		await expect(send({ content: ["a", "b"], accountId: "acct" })).resolves.toBe(true);
		expect(shownPosts).toEqual([[tweet("1"), tweet("2")]]);
	});

	it("keeps the draft open when scheduling fails", async () => {
		const { plugin, send } = await composerSend({ isConnected: true });
		plugin.settings.scheduling = {
			...plugin.settings.scheduling,
			enabled: true,
			url: "https://scheduler.invalid",
		};
		const { SelfHostedScheduler } = await import("./scheduler");
		vi.spyOn(SelfHostedScheduler.prototype, "scheduleTweet").mockRejectedValue(
			new Error("offline"),
		);

		await expect(send({ content: ["later"], postAt: 1_800_000_000_000 })).resolves.toBe(
			false,
		);
	});
});
