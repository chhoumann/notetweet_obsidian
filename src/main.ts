import { type Editor, MarkdownView, Notice, Plugin } from "obsidian";
import type { TweetV2PostTweetResult } from "twitter-api-v2";
import { DEFAULT_SETTINGS, type NoteTweetSettings } from "./settings";
import { NoteTweetSettingsTab } from "./settingsTab";
import { TwitterClient } from "./twitter";
import { SelfHostedScheduler } from "./scheduler";
import { ComposeTweetModal, type ComposeOptions } from "./Modals/ComposeTweetModal";
import { TweetsPostedModal } from "./Modals/TweetsPostedModal";
import { log } from "./log";
import { parseThread, type ScheduledTweet } from "./tweet";
import {
	type LegacyCredentialData,
	legacyCredentialsPresent,
	resolveCredentials,
	resolveSchedulerPassword,
} from "./migration";

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

export default class NoteTweet extends Plugin {
	settings!: NoteTweetSettings;
	twitter!: TwitterClient;
	scheduler: SelfHostedScheduler | null = null;

	async onload(): Promise<void> {
		await this.loadSettings();

		this.twitter = new TwitterClient(this.app);
		await this.reconnect();
		this.refreshScheduler();

		this.addCommand({
			id: "post-tweet",
			name: "Post tweet",
			callback: () => void this.composeAndPost(),
		});
		this.addCommand({
			id: "post-selected-as-tweet",
			name: "Post selection as tweet",
			editorCallback: (editor) => void this.postSelection(editor),
		});
		this.addCommand({
			id: "post-file-as-thread",
			name: "Post file as thread",
			callback: () => void this.postFileAsThread(),
		});

		this.addSettingTab(new NoteTweetSettingsTab(this.app, this));

		if (legacyCredentialsPresent(this.legacyData())) {
			new Notice(
				"NoteTweet: open settings to move your credentials into secure storage.",
			);
		}
	}

	async loadSettings(): Promise<void> {
		const loaded = ((await this.loadData()) ?? {}) as Record<string, unknown>;
		this.settings = Object.assign({}, DEFAULT_SETTINGS, loaded);
		this.settings.scheduling = Object.assign(
			{},
			DEFAULT_SETTINGS.scheduling,
			this.settings.scheduling,
		);
	}

	async saveSettings(): Promise<void> {
		await this.saveData(this.settings);
	}

	/** Connect using SecretStorage credentials (falling back to legacy plaintext). */
	async reconnect(): Promise<boolean> {
		return this.twitter.connect(resolveCredentials(this.app, this.legacyData()));
	}

	/** Rebuild the scheduler from current settings, or clear it when disabled. */
	refreshScheduler(passwordOverride?: string): void {
		const { enabled, url } = this.settings.scheduling;
		if (!enabled || !url) {
			this.scheduler = null;
			return;
		}
		const password =
			passwordOverride ?? resolveSchedulerPassword(this.app, this.legacyData());
		this.scheduler = new SelfHostedScheduler(url, password);
	}

	/** The persisted settings viewed as the legacy shape, for migration reads. */
	legacyData(): LegacyCredentialData {
		return this.settings as unknown as LegacyCredentialData;
	}

	private currentSelection(): string | null {
		const editor = this.app.workspace.getActiveViewOfType(MarkdownView)?.editor;
		return editor?.somethingSelected() ? editor.getSelection() : null;
	}

	private async composeAndPost(): Promise<void> {
		const options: ComposeOptions = {
			allowSchedule: this.settings.scheduling.enabled,
			autoSplit: this.settings.autoSplitTweets,
		};

		const selection = this.currentSelection();
		if (selection) {
			try {
				options.initialContent = parseThread(selection);
			} catch {
				options.initialText = selection;
			}
		}

		const result = await ComposeTweetModal.compose(this.app, options);
		if (!result) return;

		if (result.postAt != null) {
			await this.schedule(result.content, result.postAt);
			return;
		}

		if (!(await this.ensureConnected())) return;
		try {
			await this.showPosted(await this.twitter.postThread(result.content));
		} catch (error) {
			log.error(`Failed to post tweet: ${errorMessage(error)}`);
		}
	}

	private async postSelection(editor: Editor): Promise<void> {
		if (!editor.somethingSelected()) {
			log.warning("Nothing is selected.");
			return;
		}
		if (!(await this.ensureConnected())) return;

		try {
			const posted = await this.twitter.postTweet(editor.getSelection());
			await this.showPosted([posted]);
		} catch (error) {
			log.error(`Failed to post tweet: ${errorMessage(error)}`);
		}
	}

	private async postFileAsThread(): Promise<void> {
		const file = this.app.workspace.getActiveFile();
		if (!file || file.extension !== "md") {
			log.warning("Open a Markdown note first.");
			return;
		}

		let thread: string[];
		try {
			thread = parseThread(await this.app.vault.read(file));
		} catch (error) {
			log.warning(`Could not parse a thread in ${file.name}: ${errorMessage(error)}`);
			return;
		}

		if (!(await this.ensureConnected())) return;
		try {
			await this.showPosted(await this.twitter.postThread(thread));
		} catch (error) {
			log.error(`Failed to post thread: ${errorMessage(error)}`);
		}
	}

	private async schedule(content: string[], postAt: number): Promise<void> {
		this.refreshScheduler();
		if (!this.scheduler) {
			new Notice("Set a scheduler URL in settings first.");
			return;
		}

		const tweet: ScheduledTweet = {
			id: crypto.randomUUID(),
			content,
			postat: postAt,
		};
		try {
			await this.scheduler.scheduleTweet(tweet);
		} catch (error) {
			log.error(`Failed to schedule tweet: ${errorMessage(error)}`);
		}
	}

	private async ensureConnected(): Promise<boolean> {
		if (this.twitter.isConnected) return true;
		await this.reconnect();
		if (this.twitter.isConnected) return true;
		new Notice(
			"NoteTweet: not connected to X. Add your credentials in settings.",
		);
		return false;
	}

	private async showPosted(posts: TweetV2PostTweetResult[]): Promise<void> {
		if (posts.length === 0) return;

		const modal = new TweetsPostedModal(this.app, posts, this.twitter);
		modal.open();
		await modal.waitForClose;

		if (modal.userDeletedTweets || !this.settings.postTweetTag) return;
		for (const post of posts) await this.appendTweetTag(post.data.text);
	}

	private async appendTweetTag(text: string): Promise<void> {
		const file = this.app.workspace.getActiveFile();
		if (!file) return;
		const trimmed = text.trim();
		await this.app.vault.process(file, (data) =>
			data.replace(trimmed, `${trimmed} ${this.settings.postTweetTag}`),
		);
	}
}
