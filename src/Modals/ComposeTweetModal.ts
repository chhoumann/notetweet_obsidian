import { type App, Modal, Setting } from "obsidian";
import { log } from "../log";
import {
	MAX_TWEET_LENGTH,
	splitIntoTweets,
	type ComposeResult,
} from "../tweet";
import { promptForDateTime } from "../datetime";

export interface ComposeOptions {
	/** Pre-filled thread, one entry per tweet (edit / thread-from-selection). */
	initialContent?: string[];
	/** Raw text to seed the first tweet, auto-split when enabled. */
	initialText?: string;
	/** Show the "Schedule" button alongside the primary action. */
	allowSchedule?: boolean;
	/** Primary button label. Defaults to "Post!". */
	submitLabel?: string;
	/** Whether to split content at the character limit. Defaults to true. */
	autoSplit?: boolean;
}

const WARN_AT = MAX_TWEET_LENGTH - 50;
const DANGER_AT = MAX_TWEET_LENGTH - 25;

/**
 * Thread composer. Presents one auto-growing textarea per tweet with keyboard
 * shortcuts for adding, moving, and deleting tweets. Resolves with the composed
 * thread (and an optional `postAt` when scheduled), or `null` if dismissed.
 */
export class ComposeTweetModal extends Modal {
	private readonly textAreas: HTMLTextAreaElement[] = [];
	private textZone!: HTMLElement;
	private submitted = false;
	private result: ComposeResult | null = null;

	static compose(
		app: App,
		options: ComposeOptions = {},
	): Promise<ComposeResult | null> {
		const { promise, resolve } = Promise.withResolvers<ComposeResult | null>();
		new ComposeTweetModal(app, options, resolve).open();
		return promise;
	}

	private constructor(
		app: App,
		private readonly options: ComposeOptions,
		private readonly resolve: (result: ComposeResult | null) => void,
	) {
		super(app);
	}

	private get autoSplit(): boolean {
		return this.options.autoSplit ?? true;
	}

	onOpen(): void {
		this.contentEl.addClass("postTweetModal");
		this.setTitle(
			this.options.submitLabel === "Update"
				? "Edit scheduled tweet"
				: "Compose tweet",
		);
		this.buildHelp(this.contentEl);
		this.textZone = this.contentEl.createDiv();

		try {
			this.createFirstTextarea();
		} catch (error) {
			log.warning(String(error));
			this.close();
			return;
		}

		this.contentEl
			.createEl("button", { text: "+", cls: "nt-add-tweet" })
			.addEventListener("click", () => this.tryCreateTextarea());

		this.buildActionButtons(this.contentEl);
	}

	private buildHelp(root: HTMLElement): void {
		const tooltip = root.createDiv({ cls: "tweetTooltip", text: "Help" });
		const body = tooltip.createEl("span", { cls: "tweetTooltipBody" });
		body.appendText("Read the documentation on the ");
		body.createEl("a", {
			text: "GitHub repository",
			href: "https://github.com/chhoumann/notetweet_obsidian",
			attr: { target: "_blank", rel: "noopener" },
		});
		body.appendText(" - there are many shortcuts and features to explore.");
	}

	private createFirstTextarea(): void {
		const textarea = this.createTextarea();

		if (this.options.initialContent?.length) {
			this.fillTweets(this.options.initialContent, textarea);
		} else if (this.options.initialText) {
			const chunks = this.autoSplit
				? splitIntoTweets(this.options.initialText)
				: [this.options.initialText];
			this.fillTweets(chunks, textarea);
		}
	}

	private fillTweets(chunks: string[], first: HTMLTextAreaElement): void {
		for (const chunk of chunks) {
			try {
				const target =
					first.value.trim() === "" ? first : this.createTextarea();
				target.value = chunk;
				target.dispatchEvent(new Event("input"));
			} catch (error) {
				log.warning(String(error));
			}
		}
	}

	private createTextarea(): HTMLTextAreaElement {
		if (this.textAreas.some((area) => area.value.length === 0)) {
			throw new Error("You cannot add a new tweet while there are empty tweets.");
		}

		const textarea = this.textZone.createEl("textarea", { cls: "tweetArea" });
		this.textAreas.push(textarea);
		const counter = this.textZone.createEl("p", {
			cls: "ntLengthChecker",
			text: `0 / ${MAX_TWEET_LENGTH} characters.`,
		});

		textarea.addEventListener("input", () =>
			this.updateCounter(textarea.value.length, counter),
		);
		textarea.addEventListener("keydown", (event) =>
			this.handleKeydown(event, textarea, counter),
		);
		textarea.addEventListener("paste", (event) =>
			this.handlePaste(event, textarea),
		);

		textarea.focus();
		return textarea;
	}

	private tryCreateTextarea(): HTMLTextAreaElement | null {
		try {
			return this.createTextarea();
		} catch (error) {
			log.warning(String(error));
			return null;
		}
	}

	private updateCounter(length: number, counter: HTMLElement): void {
		counter.setText(`${length} / ${MAX_TWEET_LENGTH} characters.`);
		counter.classList.toggle("nt-length--warn", length > WARN_AT && length <= DANGER_AT);
		counter.classList.toggle("nt-length--danger", length > DANGER_AT && length < MAX_TWEET_LENGTH);
		counter.classList.toggle("nt-length--over", length >= MAX_TWEET_LENGTH);
	}

	private handlePaste(event: ClipboardEvent, textarea: HTMLTextAreaElement): void {
		if (!this.autoSplit) return;
		const pasted = event.clipboardData?.getData("text") ?? "";
		if (pasted.length + textarea.value.length <= MAX_TWEET_LENGTH) return;
		event.preventDefault();
		this.fillTweets(splitIntoTweets(pasted), textarea);
	}

	private handleKeydown(
		event: KeyboardEvent,
		textarea: HTMLTextAreaElement,
		counter: HTMLElement,
	): void {
		const index = this.textAreas.indexOf(textarea);
		const empty = textarea.value.length === 0;

		if (event.code === "Backspace" && empty && this.textAreas.length > 1) {
			event.preventDefault();
			this.deleteTweet(textarea, counter);
			return;
		}

		const enter = event.code === "Enter" || event.code === "NumpadEnter";

		if (
			(event.code === "Enter" &&
				textarea.value.length >= MAX_TWEET_LENGTH &&
				this.autoSplit) ||
			(enter && event.altKey)
		) {
			event.preventDefault();
			this.tryCreateTextarea();
			return;
		}

		if (event.code === "Enter" && event.shiftKey) {
			event.preventDefault();
			this.insertTweet(index);
			return;
		}

		if (event.code === "Enter" && event.ctrlKey) {
			event.preventDefault();
			this.insertTweet(index + 1);
			return;
		}

		if (event.ctrlKey && !event.shiftKey && event.code === "ArrowUp" && index > 0) {
			this.textAreas[index - 1].focus();
			return;
		}
		if (
			event.ctrlKey &&
			!event.shiftKey &&
			event.code === "ArrowDown" &&
			index < this.textAreas.length - 1
		) {
			this.textAreas[index + 1].focus();
			return;
		}

		if (
			event.ctrlKey &&
			event.shiftKey &&
			event.code === "ArrowDown" &&
			index < this.textAreas.length - 1
		) {
			event.preventDefault();
			this.swapTweets(index, index + 1);
			return;
		}
		if (event.ctrlKey && event.shiftKey && event.code === "ArrowUp" && index > 0) {
			event.preventDefault();
			this.swapTweets(index, index - 1);
			return;
		}

		if (event.ctrlKey && event.shiftKey && event.code === "Delete") {
			event.preventDefault();
			if (this.textAreas.length === 1) {
				textarea.value = "";
				textarea.dispatchEvent(new Event("input"));
			} else {
				this.deleteTweet(textarea, counter);
			}
		}
	}

	private deleteTweet(textarea: HTMLTextAreaElement, counter: HTMLElement): void {
		const index = this.textAreas.indexOf(textarea);
		this.textAreas.splice(index, 1);
		textarea.remove();
		counter.remove();
		this.textAreas[index === 0 ? 0 : index - 1]?.focus();
	}

	private swapTweets(a: number, b: number): void {
		const temp = this.textAreas[a].value;
		this.textAreas[a].value = this.textAreas[b].value;
		this.textAreas[b].value = temp;
		this.textAreas[a].dispatchEvent(new Event("input"));
		this.textAreas[b].dispatchEvent(new Event("input"));
		this.textAreas[b].focus();
	}

	/** Insert an empty tweet at `index`, shifting later tweets' text down. */
	private insertTweet(index: number): void {
		if (!this.tryCreateTextarea()) return;
		for (let i = this.textAreas.length - 1; i > index; i--) {
			this.textAreas[i].value = this.textAreas[i - 1].value;
			this.textAreas[i].dispatchEvent(new Event("input"));
		}
		this.textAreas[index].value = "";
		this.textAreas[index].dispatchEvent(new Event("input"));
		this.textAreas[index].focus();
	}

	private getThreadContent(): string[] | null {
		const content = this.textAreas.map((area) => area.value);

		if (this.autoSplit) {
			if (content.some((text) => text.length > MAX_TWEET_LENGTH || text === "")) {
				log.warning("At least one of your tweets is too long or empty.");
				return null;
			}
		} else if (content.some((text) => text === "")) {
			log.warning("At least one of your tweets is empty.");
			return null;
		}

		return content;
	}

	private buildActionButtons(root: HTMLElement): void {
		const row = new Setting(root);
		row.addButton((button) =>
			button
				.setButtonText(this.options.submitLabel ?? "Post!")
				.setCta()
				.onClick(() => this.submitPost()),
		);
		if (this.options.allowSchedule) {
			row.addButton((button) =>
				button.setButtonText("Schedule").onClick(() => this.submitSchedule()),
			);
		}
	}

	private submitPost(): void {
		const content = this.getThreadContent();
		if (!content) return;
		this.result = { content };
		this.submitted = true;
		this.close();
	}

	private async submitSchedule(): Promise<void> {
		const content = this.getThreadContent();
		if (!content) return;

		let postAt: number | null;
		try {
			postAt = await promptForDateTime(this.app);
		} catch (error) {
			log.error(String(error));
			return;
		}
		if (postAt === null) return;

		this.result = { content, postAt };
		this.submitted = true;
		this.close();
	}

	onClose(): void {
		this.contentEl.empty();
		this.resolve(this.submitted ? this.result : null);
	}
}
