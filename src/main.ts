import { type Editor, MarkdownView, Notice, Plugin } from "obsidian";
import type { PostedTweet } from "./xApi";
import {
	DEFAULT_SETTINGS,
	normalizeAccountSettings,
	type NoteTweetSettings,
} from "./settings";
import { NoteTweetSettingsTab } from "./settingsTab";
import { TwitterClient } from "./twitter";
import { SelfHostedScheduler } from "./scheduler";
import { ComposeTweetModal, type ComposeOptions } from "./Modals/ComposeTweetModal";
import { TweetsPostedModal } from "./Modals/TweetsPostedModal";
import { log } from "./log";
import { parseThread, type ScheduledTweet } from "./tweet";
import {
	clearFixedTwitterSecrets,
	type LegacyCredentialData,
	legacyCredentialsPresent,
	resolveSchedulerPassword,
	stageFixedSecretMigration,
} from "./migration";
import { getAccountCredentials, type TwitterCredentials } from "./secrets";

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

export default class NoteTweet extends Plugin {
	settings!: NoteTweetSettings;
	scheduler: SelfHostedScheduler | null = null;

	async onload(): Promise<void> {
		await this.loadSettings();
		const migrated = stageFixedSecretMigration(this.app, this.settings);
		if (migrated) {
			await this.saveSettings();
			clearFixedTwitterSecrets(this.app);
			new Notice(
				`NoteTweet: existing credentials moved to the ${migrated.name} account.`,
			);
		}
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
		this.settings.accounts = Array.isArray(loaded.accounts)
			? (loaded.accounts as NoteTweetSettings["accounts"])
			: [];
		this.settings.scheduling = Object.assign(
			{},
			DEFAULT_SETTINGS.scheduling,
			this.settings.scheduling,
		);
		normalizeAccountSettings(this.settings);
	}

	async saveSettings(): Promise<void> {
		await this.saveData(this.settings);
	}

	/** Build and verify an account-scoped client for one direct posting action. */
	async connectAccount(accountId: string): Promise<TwitterClient> {
		const client = new TwitterClient(this.app);
		const exists = this.settings.accounts.some(({ id }) => id === accountId);
		if (exists) await client.connect(getAccountCredentials(this.app, accountId));
		return client;
	}

	async verifyCredentials(credentials: TwitterCredentials): Promise<boolean> {
		return new TwitterClient(this.app).connect(credentials);
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
			accounts: this.settings.accounts,
			selectedAccountId: this.settings.defaultAccountId,
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

		const client = await this.clientForAccount(result.accountId);
		if (!client) return;
		try {
			await this.showPosted(await client.postThread(result.content), client);
		} catch (error) {
			log.error(`Failed to post tweet: ${errorMessage(error)}`);
		}
	}

	private async postSelection(editor: Editor): Promise<void> {
		if (!editor.somethingSelected()) {
			log.warning("Nothing is selected.");
			return;
		}
		const client = await this.clientForAccount(this.settings.defaultAccountId);
		if (!client) return;

		try {
			const posted = await client.postTweet(editor.getSelection());
			await this.showPosted([posted], client);
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

		const client = await this.clientForAccount(this.settings.defaultAccountId);
		if (!client) return;
		try {
			await this.showPosted(await client.postThread(thread), client);
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

	private async clientForAccount(
		accountId: string | undefined,
	): Promise<TwitterClient | null> {
		if (!accountId) {
			new Notice("NoteTweet: add an X account in settings first.");
			return null;
		}
		const client = await this.connectAccount(accountId);
		if (client.isConnected) return client;
		new Notice(
			"NoteTweet: that X account is not connected. Check its credentials in settings.",
		);
		return null;
	}

	private async showPosted(
		posts: PostedTweet[],
		client: TwitterClient,
	): Promise<void> {
		if (posts.length === 0) return;

		const modal = new TweetsPostedModal(this.app, posts, client);
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
