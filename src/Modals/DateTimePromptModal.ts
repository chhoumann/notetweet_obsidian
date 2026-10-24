import { type App, ButtonComponent, Modal } from "obsidian";
import { deferred } from "../deferred";
import { fromDateTimeInput, nextFullHour, toDateTimeInput } from "../datetime";

/**
 * Ask when to post with the platform's date and time picker. Resolves with the
 * chosen timestamp, or `null` when dismissed.
 */
export function promptForDateTime(
	app: App,
	initial = nextFullHour(Date.now()),
): Promise<number | null> {
	const { promise, resolve } = deferred<number | null>();
	new DateTimePromptModal(app, initial, resolve).open();
	return promise;
}

/** Picks a future date and time with the platform's native picker. */
export class DateTimePromptModal extends Modal {
	private value: number | null;
	private submitted = false;
	private button!: ButtonComponent;
	private errorEl!: HTMLElement;

	constructor(
		app: App,
		initial: number,
		private readonly resolve: (value: number | null) => void,
	) {
		super(app);
		this.value = initial;
		this.setTitle("Schedule post");
	}

	onOpen(): void {
		this.modalEl.addClass("mod-form", "nt-schedule-modal");
		const input = this.contentEl.createEl("input", {
			cls: "nt-schedule-input",
			type: "datetime-local",
			attr: { "aria-label": "Post at", min: toDateTimeInput(Date.now()) },
			value: toDateTimeInput(this.value ?? Date.now()),
		});
		input.addEventListener("input", () => {
			this.value = fromDateTimeInput(input.value);
			this.refresh();
		});
		input.addEventListener("keydown", (event) => {
			if (event.key === "Enter") {
				event.preventDefault();
				this.submit();
			}
		});
		this.errorEl = this.contentEl.createDiv({ cls: "nt-schedule-error" });

		const buttons = this.modalEl.createDiv({ cls: "modal-button-container" });
		this.button = new ButtonComponent(buttons)
			.setButtonText("Schedule")
			.setCta()
			.onClick(() => this.submit());
		this.refresh();
	}

	private get valid(): boolean {
		return this.value !== null && this.value > Date.now();
	}

	private refresh(): void {
		this.button.setDisabled(!this.valid);
		this.errorEl.setText(
			this.value === null || this.valid ? "" : "Pick a time in the future.",
		);
	}

	private submit(): void {
		if (!this.valid) return;
		this.submitted = true;
		this.close();
	}

	onClose(): void {
		this.resolve(this.submitted ? this.value : null);
		this.contentEl.empty();
	}
}
