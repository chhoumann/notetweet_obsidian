import {App, Modal, TextComponent} from "obsidian";

export default class GenericInputPrompt extends Modal {
    private resolvePromise: (input: string) => void;
    private input: string;
    public waitForClose: Promise<string>;
    private rejectPromise: (reason?: any) => void;
    private didSubmit: boolean = false;

    public static Prompt(app: App, header: string, placeholder?: string, value?: string): Promise<string> {
        const newPromptModal = new GenericInputPrompt(app, header, placeholder, value);
        return newPromptModal.waitForClose;
    }

    private constructor(app: App, private header: string, placeholder?: string, value?: string) {
        super(app);

        this.waitForClose = new Promise<string>(
            (resolve, reject) => {
                this.resolvePromise = resolve;
                this.rejectPromise = reject;
            }
        );

        this.open();
        this.display();
    }

    private display() {
        this.contentEl.empty();
        this.addHeader();
        this.addInput();
    }

    onOpen() {
        super.onOpen();
    }

    onClose() {
        super.onClose();

        if(!this.didSubmit) this.rejectPromise("No input given.");
        else this.resolvePromise(this.input);
    }

    private addHeader() {
        this.contentEl.createEl('h3', {text: this.header});
    }

    private addInput() {
        const inputEl: TextComponent = new TextComponent(this.contentEl);
        inputEl.setPlaceholder("today at 11:00");
        inputEl.inputEl.style.width = "100%";
        inputEl.inputEl.focus();
        inputEl.inputEl.select();

        inputEl.inputEl.addEventListener('keypress', ev => {
            if (ev.key === 'Enter') {
                this.resolvePromise(inputEl.getValue());
                this.didSubmit = true;
                this.close();
            }
        })
    }
}
