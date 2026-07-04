import {
	type App,
	FuzzySuggestModal,
	Modal,
	type TFile,
	setIcon,
} from "obsidian";
import { log } from "../log";
import {
	MAX_TWEET_LENGTH,
	splitIntoTweets,
	type ComposeResult,
} from "../tweet";
import { promptForDateTime } from "../datetime";

export interface ComposeOptions {
	/** Pre-filled thread, one entry per post (edit / thread-from-selection). */
	initialContent?: string[];
	/** Raw text to seed the first post, auto-split when enabled. */
	initialText?: string;
	/** Show the "Schedule" button alongside the primary action. */
	allowSchedule?: boolean;
	/** Primary button label. Defaults to "Post". */
	submitLabel?: string;
	/** Whether to split content at the character limit. Defaults to true. */
	autoSplit?: boolean;
}

/** Character count starts showing once this many remain. */
const COUNTDOWN_FROM = 30;
/** A run of this many newlines is the "start a new post" gesture. */
const BREAK_RUN = "\n\n\n";
/** Twitter accepts at most four images per post. */
const MAX_MEDIA = 4;
const IMAGE_EXTENSIONS: Record<string, true> = {
	gif: true,
	jpg: true,
	jpeg: true,
	tif: true,
	tiff: true,
	png: true,
	webp: true,
	bmp: true,
};

/** Extensions for clipboard image types we can save to the vault. */
const EXTENSION_BY_MIME: Record<string, string> = {
	"image/png": "png",
	"image/jpeg": "jpg",
	"image/gif": "gif",
	"image/webp": "webp",
	"image/bmp": "bmp",
	"image/tiff": "tiff",
};

/** `YYYYMMDDHHmmss` stamp for pasted-image filenames, matching Obsidian's own. */
function pasteStamp(): string {
	const now = new Date();
	const pad = (value: number) => String(value).padStart(2, "0");
	return (
		`${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}` +
		`${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`
	);
}

/** One composed post: its card, editor, count, attachments, and controls. */
interface PostRow {
	el: HTMLElement;
	node: HTMLElement;
	card: HTMLElement;
	textarea: HTMLTextAreaElement;
	count: HTMLElement;
	attachEl: HTMLElement;
	attachments: TFile[];
	moveUp: HTMLButtonElement;
	moveDown: HTMLButtonElement;
	remove: HTMLButtonElement;
}

/** Fuzzy picker over the vault's image files, for attaching media to a post. */
class ImagePickerModal extends FuzzySuggestModal<TFile> {
	constructor(
		app: App,
		private readonly files: TFile[],
		private readonly onPick: (file: TFile) => void,
	) {
		super(app);
		this.setPlaceholder("Attach an image from your vault\u2026");
	}

	getItems(): TFile[] {
		return this.files;
	}

	getItemText(file: TFile): string {
		return file.path;
	}

	onChooseItem(file: TFile): void {
		this.onPick(file);
	}
}

/**
 * Thread composer. One roomy card per post on a connected rail (shown only for
 * threads), with hover controls to attach images, reorder, and delete, a
 * character count that surfaces near the limit, keyboard shortcuts, and a
 * triple-newline gesture to start a new post. Resolves with the composed thread
 * (and an optional `postAt` when scheduled), or `null` if dismissed.
 */
export class ComposeTweetModal extends Modal {
	private readonly rows: PostRow[] = [];
	private thread!: HTMLElement;
	private statusEl!: HTMLElement;
	private postButton!: HTMLButtonElement;
	private scheduleButton: HTMLButtonElement | null = null;
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
		this.modalEl.addClass("nt-compose-modal");
		this.contentEl.addClass("postTweetModal");
		this.setTitle(
			this.options.submitLabel === "Update"
				? "Edit scheduled post"
				: "Compose post",
		);

		this.thread = this.contentEl.createDiv({ cls: "nt-thread" });

		try {
			this.seedContent();
		} catch (error) {
			log.warning(String(error));
			this.close();
			return;
		}

		this.buildAddButton(this.contentEl);
		this.buildFooter(this.contentEl);
		this.refreshState();
	}

	private seedContent(): void {
		const first = this.makeRow();

		if (this.options.initialContent?.length) {
			this.fillPosts(this.options.initialContent, first);
		} else if (this.options.initialText) {
			const chunks = this.autoSplit
				? splitIntoTweets(this.options.initialText)
				: [this.options.initialText];
			this.fillPosts(chunks, first);
		}

		this.rows[0]?.textarea.focus();
	}

	private fillPosts(chunks: string[], first: PostRow): void {
		for (const chunk of chunks) {
			const target =
				first.textarea.value.trim() === "" ? first : this.makeRow();
			target.textarea.value = chunk;
			this.update(target);
		}
	}

	/** Build one post card and insert it at `atIndex` (default: append). */
	private makeRow(value = "", atIndex = this.rows.length): PostRow {
		const el = this.thread.createDiv({ cls: "nt-post" });
		const rail = el.createDiv({ cls: "nt-rail" });
		const node = rail.createDiv({ cls: "nt-node" });
		const body = el.createDiv({ cls: "nt-body" });
		const card = body.createDiv({ cls: "nt-card" });

		const editor = card.createDiv({ cls: "nt-editor" });
		const textarea = editor.createEl("textarea", {
			cls: "tweetArea",
			attr: { placeholder: "What do you want to say?", rows: "1" },
		});
		textarea.value = value;
		const count = editor.createDiv({ cls: "nt-count" });

		const attachEl = card.createDiv({ cls: "nt-attachments" });

		const controls = card.createDiv({ cls: "nt-controls" });
		const attach = this.iconButton(controls, "image", "Attach image");
		const moveUp = this.iconButton(controls, "arrow-up", "Move up");
		const moveDown = this.iconButton(controls, "arrow-down", "Move down");
		const remove = this.iconButton(controls, "trash-2", "Delete post", true);

		const row: PostRow = {
			el,
			node,
			card,
			textarea,
			count,
			attachEl,
			attachments: [],
			moveUp,
			moveDown,
			remove,
		};

		if (atIndex < this.rows.length) {
			this.thread.insertBefore(el, this.rows[atIndex].el);
			this.rows.splice(atIndex, 0, row);
		} else {
			this.rows.push(row);
		}

		textarea.addEventListener("input", () => {
			if (this.splitOnBlankLines(row)) return;
			this.update(row);
			this.refreshState();
		});
		textarea.addEventListener("focus", () => this.setActive(row));
		textarea.addEventListener("keydown", (event) =>
			this.handleKeydown(event, row),
		);
		textarea.addEventListener("paste", (event) => this.handlePaste(event, row));

		attach.addEventListener("click", () => this.pickImage(row));
		moveUp.addEventListener("click", () => this.moveRow(row, -1));
		moveDown.addEventListener("click", () => this.moveRow(row, 1));
		remove.addEventListener("click", () => this.deleteRow(row));

		this.update(row);
		return row;
	}

	private iconButton(
		parent: HTMLElement,
		icon: string,
		label: string,
		danger = false,
	): HTMLButtonElement {
		const button = parent.createEl("button", {
			cls: danger ? "nt-icon-btn nt-danger" : "nt-icon-btn",
			attr: { type: "button", "aria-label": label, title: label },
		});
		setIcon(button, icon);
		return button;
	}

	private buildAddButton(root: HTMLElement): void {
		const add = root.createEl("button", {
			cls: "nt-add",
			attr: { type: "button" },
		});
		setIcon(add.createSpan({ cls: "nt-add-icon" }), "plus");
		add.createSpan({ text: "Add post" });
		add.addEventListener("click", () => this.appendRow());
	}

	private buildFooter(root: HTMLElement): void {
		const footer = root.createDiv({ cls: "nt-footer" });
		this.statusEl = footer.createDiv({ cls: "nt-footer-status" });

		const actions = footer.createDiv({ cls: "nt-footer-actions" });
		if (this.options.allowSchedule) {
			this.scheduleButton = actions.createEl("button", {
				cls: "nt-btn nt-btn-ghost",
				text: "Schedule",
				attr: { type: "button" },
			});
			this.scheduleButton.addEventListener("click", () =>
				void this.submitSchedule(),
			);
		}
		this.postButton = actions.createEl("button", {
			cls: "nt-btn nt-btn-cta",
			text: this.options.submitLabel ?? "Post",
			attr: { type: "button" },
		});
		this.postButton.addEventListener("click", () => this.submitPost());
	}

	private pickImage(row: PostRow): void {
		if (row.attachments.length >= MAX_MEDIA) {
			log.warning(`A post can hold at most ${MAX_MEDIA} images.`);
			return;
		}
		const images = this.app.vault
			.getFiles()
			.filter((file) => IMAGE_EXTENSIONS[file.extension.toLowerCase()] === true)
			.filter((file) => !row.attachments.includes(file));
		if (images.length === 0) {
			log.warning("No image files found in your vault.");
			return;
		}
		new ImagePickerModal(this.app, images, (file) => {
			row.attachments.push(file);
			this.renderAttachments(row);
			this.refreshState();
			row.textarea.focus();
		}).open();
	}

	private renderAttachments(row: PostRow): void {
		row.attachEl.empty();
		for (const file of row.attachments) {
			const chip = row.attachEl.createDiv({ cls: "nt-attachment" });
			chip.createEl("img", {
				attr: { src: this.app.vault.getResourcePath(file), alt: file.name },
			});
			const remove = chip.createEl("button", {
				cls: "nt-attachment-remove",
				attr: { type: "button", "aria-label": `Remove ${file.name}` },
			});
			setIcon(remove, "x");
			remove.addEventListener("click", () => {
				row.attachments = row.attachments.filter((item) => item !== file);
				this.renderAttachments(row);
				this.refreshState();
			});
		}
	}

	private setActive(row: PostRow): void {
		for (const other of this.rows) {
			other.el.toggleClass("is-active", other === row);
		}
	}

	/** Repaint one row's character count from its current length. */
	private update(row: PostRow): void {
		const length = row.textarea.value.length;
		const remaining = MAX_TWEET_LENGTH - length;
		const shown = remaining <= COUNTDOWN_FROM;
		const over = this.autoSplit && length > MAX_TWEET_LENGTH;

		row.count.toggleClass("is-shown", shown);
		row.count.toggleClass("is-over", over);
		row.card.toggleClass("has-count", shown);
		row.el.toggleClass("is-over", over);
		if (shown) row.count.setText(String(remaining));
	}

	/**
	 * Recompute thread-wide chrome: rail visibility, node numbering, control
	 * availability, and the footer validity that gates the actions.
	 */
	private refreshState(): void {
		const count = this.rows.length;
		this.thread.toggleClass("is-single", count <= 1);

		this.rows.forEach((row, index) => {
			row.node.setText(String(index + 1));
			row.moveUp.disabled = index === 0;
			row.moveDown.disabled = index === count - 1;
			row.remove.disabled = count === 1 && this.isEmpty(row);
		});

		const { ok, reason } = this.validate();
		this.statusEl.setText(reason ?? "");
		this.statusEl.toggleClass("is-blocked", Boolean(reason));
		this.postButton.disabled = !ok;
		if (this.scheduleButton) this.scheduleButton.disabled = !ok;
	}

	private handlePaste(event: ClipboardEvent, row: PostRow): void {
		const images = Array.from(event.clipboardData?.files ?? []).filter((file) =>
			file.type.startsWith("image/"),
		);
		if (images.length > 0) {
			event.preventDefault();
			void this.attachPastedImages(row, images);
			return;
		}

		if (!this.autoSplit) return;
		const pasted = event.clipboardData?.getData("text") ?? "";
		if (pasted.length + row.textarea.value.length <= MAX_TWEET_LENGTH) return;
		event.preventDefault();
		this.fillPosts(splitIntoTweets(pasted), row);
		this.refreshState();
	}

	/** Save clipboard images into the vault, then attach them to the post. */
	private async attachPastedImages(row: PostRow, files: File[]): Promise<void> {
		for (const file of files) {
			if (row.attachments.length >= MAX_MEDIA) {
				log.warning(`A post can hold at most ${MAX_MEDIA} images.`);
				break;
			}
			const extension = EXTENSION_BY_MIME[file.type];
			if (!extension) {
				log.warning(`Unsupported image type: ${file.type}.`);
				continue;
			}
			try {
				const name = `Pasted image ${pasteStamp()}.${extension}`;
				const path = await this.app.fileManager.getAvailablePathForAttachment(name);
				const saved = await this.app.vault.createBinary(path, await file.arrayBuffer());
				row.attachments.push(saved);
				this.renderAttachments(row);
				this.refreshState();
			} catch (error) {
				log.error(`Could not save the pasted image: ${String(error)}`);
			}
		}
	}

	private handleKeydown(event: KeyboardEvent, row: PostRow): void {
		const index = this.rows.indexOf(row);
		const empty = row.textarea.value.length === 0;

		if (event.code === "Backspace" && empty && this.rows.length > 1) {
			event.preventDefault();
			this.deleteRow(row);
			return;
		}

		const enter = event.code === "Enter" || event.code === "NumpadEnter";

		if (
			(event.code === "Enter" &&
				row.textarea.value.length >= MAX_TWEET_LENGTH &&
				this.autoSplit) ||
			(enter && event.altKey)
		) {
			event.preventDefault();
			this.appendRow();
			return;
		}

		if (event.code === "Enter" && event.shiftKey) {
			event.preventDefault();
			this.insertRow(index);
			return;
		}

		if (event.code === "Enter" && event.ctrlKey) {
			event.preventDefault();
			this.insertRow(index + 1);
			return;
		}

		if (event.ctrlKey && !event.shiftKey && event.code === "ArrowUp" && index > 0) {
			this.rows[index - 1].textarea.focus();
			return;
		}
		if (
			event.ctrlKey &&
			!event.shiftKey &&
			event.code === "ArrowDown" &&
			index < this.rows.length - 1
		) {
			this.rows[index + 1].textarea.focus();
			return;
		}

		if (
			event.ctrlKey &&
			event.shiftKey &&
			event.code === "ArrowDown" &&
			index < this.rows.length - 1
		) {
			event.preventDefault();
			this.swapRows(index, index + 1);
			return;
		}
		if (event.ctrlKey && event.shiftKey && event.code === "ArrowUp" && index > 0) {
			event.preventDefault();
			this.swapRows(index, index - 1);
			return;
		}

		if (event.ctrlKey && event.shiftKey && event.code === "Delete") {
			event.preventDefault();
			this.deleteRow(row);
		}
	}

	/** Split the current post at the first run of blank lines. */
	private splitOnBlankLines(row: PostRow): boolean {
		const value = row.textarea.value;
		const index = value.indexOf(BREAK_RUN);
		if (index === -1) return false;

		row.textarea.value = value.slice(0, index);
		this.update(row);
		const next = this.makeRow(
			value.slice(index + BREAK_RUN.length),
			this.rows.indexOf(row) + 1,
		);
		this.refreshState();
		next.textarea.focus();
		next.textarea.setSelectionRange(0, 0);
		return true;
	}

	private appendRow(): PostRow | null {
		if (this.rows.some((row) => this.isEmpty(row))) {
			log.warning("Finish the empty post before adding another.");
			return null;
		}
		const row = this.makeRow();
		this.refreshState();
		row.textarea.focus();
		return row;
	}

	private insertRow(index: number): void {
		if (this.rows.some((row) => this.isEmpty(row))) {
			log.warning("Finish the empty post before adding another.");
			return;
		}
		const row = this.makeRow("", index);
		this.refreshState();
		row.textarea.focus();
	}

	private deleteRow(row: PostRow): void {
		if (this.rows.length === 1) {
			row.textarea.value = "";
			row.attachments = [];
			this.renderAttachments(row);
			this.update(row);
			this.refreshState();
			return;
		}
		const index = this.rows.indexOf(row);
		this.rows.splice(index, 1);
		row.el.remove();
		this.refreshState();
		this.rows[index === 0 ? 0 : index - 1]?.textarea.focus();
	}

	private swapRows(a: number, b: number): void {
		[this.rows[a], this.rows[b]] = [this.rows[b], this.rows[a]];
		this.thread.insertBefore(
			this.rows[Math.min(a, b)].el,
			this.rows[Math.max(a, b)].el,
		);
		this.refreshState();
		this.rows[b].textarea.focus();
	}

	private moveRow(row: PostRow, direction: -1 | 1): void {
		const index = this.rows.indexOf(row);
		const target = index + direction;
		if (target < 0 || target >= this.rows.length) return;
		this.swapRows(index, target);
	}

	private isEmpty(row: PostRow): boolean {
		return row.textarea.value.length === 0 && row.attachments.length === 0;
	}

	/**
	 * Validate the thread. `ok` is true when every post has text or an image and
	 * none exceed the limit (when auto-split is on); `reason` explains a block, or
	 * is `null` when the thread is simply untouched.
	 */
	private validate(): { ok: boolean; reason: string | null } {
		if (this.rows.every((row) => this.isEmpty(row))) {
			return { ok: false, reason: null };
		}
		if (
			this.autoSplit &&
			this.rows.some((row) => row.textarea.value.length > MAX_TWEET_LENGTH)
		) {
			return { ok: false, reason: "A post is over 280 characters" };
		}
		if (this.rows.some((row) => this.isEmpty(row))) {
			return { ok: false, reason: "A post in the thread is empty" };
		}
		return { ok: true, reason: null };
	}

	/** Compose the postable text for each row, appending image links at the end. */
	private collectContent(): string[] {
		return this.rows.map((row) => {
			const text = row.textarea.value;
			if (row.attachments.length === 0) return text;
			const links = row.attachments.map((file) => `[[${file.path}]]`).join(" ");
			return text.length > 0 ? `${text}\n${links}` : links;
		});
	}

	private submitPost(): void {
		if (!this.validate().ok) return;
		this.result = { content: this.collectContent() };
		this.submitted = true;
		this.close();
	}

	private async submitSchedule(): Promise<void> {
		if (!this.validate().ok) return;

		let postAt: number | null;
		try {
			postAt = await promptForDateTime(this.app);
		} catch (error) {
			log.error(String(error));
			return;
		}
		if (postAt === null) return;

		this.result = { content: this.collectContent(), postAt };
		this.submitted = true;
		this.close();
	}

	onClose(): void {
		this.contentEl.empty();
		this.resolve(this.submitted ? this.result : null);
	}
}
