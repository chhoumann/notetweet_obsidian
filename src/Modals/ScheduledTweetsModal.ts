import { type App, Modal, Setting } from "obsidian";
import { log } from "../log";
import type { Scheduler } from "../scheduler";
import type { ScheduledTweet } from "../tweet";
import { formatDateTime, promptForDateTime } from "../datetime";
import { ComposeTweetModal } from "./ComposeTweetModal";

/** Lists the tweets held by the scheduler and manages them (delete/reschedule/edit). */
export class ScheduledTweetsModal extends Modal {
	constructor(app: App, private readonly scheduler: Scheduler) {
		super(app);
	}

	async onOpen(): Promise<void> {
		await this.render();
	}

	private async render(): Promise<void> {
		const { contentEl } = this;
		contentEl.empty();
		contentEl.addClass("postTweetModal");

		let tweets: ScheduledTweet[];
		try {
			tweets = await this.scheduler.getScheduledTweets();
		} catch (error) {
			log.error(`Could not load scheduled tweets: ${error}`);
			this.close();
			return;
		}

		this.setTitle(`Scheduled tweets (${tweets.length})`);

		if (tweets.length === 0) {
			contentEl.createEl("p", { text: "No scheduled tweets. Go write some!" });
			return;
		}

		const container = contentEl.createDiv({ cls: "scheduledTweetsContainer" });
		for (const tweet of tweets) this.renderRow(tweet, container);
	}

	private renderRow(tweet: ScheduledTweet, container: HTMLElement): void {
		const row = container.createDiv({ cls: "scheduledTweet" });
		for (const item of tweet.content) {
			row.createDiv({ cls: "tweetContainer" }).createEl("span", { text: item });
		}
		row.createEl("p", {
			cls: "nt-scheduled-when",
			text: `Scheduled for: ${formatDateTime(tweet.postat)}`,
		});

		new Setting(row)
			.addButton((button) =>
				button
					.setButtonText("Delete")
					.setWarning()
					.onClick(() => this.deleteTweet(tweet)),
			)
			.addButton((button) =>
				button.setButtonText("Reschedule").onClick(() => this.reschedule(tweet)),
			)
			.addButton((button) =>
				button
					.setButtonText("Edit")
					.setCta()
					.onClick(() => this.editTweet(tweet)),
			);
	}

	private async deleteTweet(tweet: ScheduledTweet): Promise<void> {
		try {
			await this.scheduler.deleteScheduledTweet(tweet);
			await this.render();
		} catch (error) {
			log.error(`Could not delete scheduled tweet: ${error}`);
		}
	}

	private async reschedule(tweet: ScheduledTweet): Promise<void> {
		let postAt: number | null;
		try {
			postAt = await promptForDateTime(this.app);
		} catch (error) {
			log.error(String(error));
			return;
		}
		if (postAt === null) return;

		try {
			await this.scheduler.updateTweet({ ...tweet, postat: postAt });
			await this.render();
		} catch (error) {
			log.error(`Could not reschedule tweet: ${error}`);
		}
	}

	private async editTweet(tweet: ScheduledTweet): Promise<void> {
		const result = await ComposeTweetModal.compose(this.app, {
			initialContent: tweet.content,
			submitLabel: "Update",
			autoSplit: false,
		});
		if (!result) return;

		try {
			await this.scheduler.updateTweet({ ...tweet, content: result.content });
			await this.render();
		} catch (error) {
			log.error(`Could not update tweet: ${error}`);
		}
	}

	onClose(): void {
		this.contentEl.empty();
	}
}
