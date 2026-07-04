import { type App, Modal, Notice, Setting } from "obsidian";
import type { PostedTweet } from "../xApi";
import type { TwitterClient } from "../twitter";

/**
 * Confirmation shown after posting. Links to each live tweet and offers to
 * delete the whole thread again. `waitForClose` resolves when dismissed, and
 * `userDeletedTweets` reports whether the user deleted them.
 */
export class TweetsPostedModal extends Modal {
	public userDeletedTweets = false;
	public readonly waitForClose: Promise<void>;
	private readonly resolveClose: () => void;

	constructor(
		app: App,
		private readonly posts: PostedTweet[],
		private readonly twitter: TwitterClient,
	) {
		super(app);
		const { promise, resolve } = Promise.withResolvers<void>();
		this.waitForClose = promise;
		this.resolveClose = resolve;
	}

	onOpen(): void {
		const { contentEl } = this;
		this.setTitle(
			this.posts.length > 1 ? "Your tweets are live!" : "Your tweet is live!",
		);

		const list = contentEl.createDiv({ cls: "nt-posted-list" });
		for (const post of this.posts) {
			list.createEl("a", {
				text: post.data.text,
				href: `https://x.com/i/status/${post.data.id}`,
				attr: { target: "_blank", rel: "noopener" },
			});
		}

		new Setting(contentEl)
			.addButton((button) =>
				button
					.setButtonText("Delete")
					.setDestructive()
					.onClick(() => this.deletePosted()),
			)
			.addButton((button) =>
				button
					.setButtonText("Great!")
					.setCta()
					.onClick(() => this.close()),
			);
	}

	private async deletePosted(): Promise<void> {
		const deleted = await this.twitter.deleteTweets(
			this.posts.map((post) => ({ id: post.data.id })),
		);

		if (!deleted) {
			new Notice("Could not delete tweet(s).");
			return;
		}

		this.userDeletedTweets = true;
		const plural = this.posts.length > 1 ? "s" : "";
		new Notice(`${this.posts.length} tweet${plural} deleted.`);
		this.close();
	}

	onClose(): void {
		this.contentEl.empty();
		this.resolveClose();
	}
}
