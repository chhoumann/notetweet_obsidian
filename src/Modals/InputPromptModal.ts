import { type App, Modal, Setting } from "obsidian";

interface InputPromptOptions {
	placeholder?: string;
	value?: string;
	password?: boolean;
}

/**
 * A small single-field prompt. Resolves with the entered value, or `null` when
 * the user dismisses the modal without submitting.
 */
export class InputPromptModal extends Modal {
	private submitted = false;
	private value: string;

	static prompt(
		app: App,
		header: string,
		options: InputPromptOptions = {},
	): Promise<string | null> {
		const { promise, resolve } = Promise.withResolvers<string | null>();
		new InputPromptModal(app, header, options, resolve).open();
		return promise;
	}

	private constructor(
		app: App,
		header: string,
		private readonly options: InputPromptOptions,
		private readonly resolve: (value: string | null) => void,
	) {
		super(app);
		this.value = options.value ?? "";
		this.setTitle(header);
	}

	onOpen(): void {
		new Setting(this.contentEl).addText((text) => {
			if (this.options.password) text.inputEl.type = "password";
			text
				.setPlaceholder(this.options.placeholder ?? "")
				.setValue(this.value)
				.onChange((value) => (this.value = value));
			text.inputEl.addEventListener("keydown", (event) => {
				if (event.key === "Enter") {
					event.preventDefault();
					this.submit();
				}
			});
			window.setTimeout(() => {
				text.inputEl.focus();
				text.inputEl.select();
			}, 0);
		});

		new Setting(this.contentEl).addButton((button) =>
			button
				.setButtonText("OK")
				.setCta()
				.onClick(() => this.submit()),
		);
	}

	private submit(): void {
		this.submitted = true;
		this.close();
	}

	onClose(): void {
		this.resolve(this.submitted ? this.value : null);
		this.contentEl.empty();
	}
}
