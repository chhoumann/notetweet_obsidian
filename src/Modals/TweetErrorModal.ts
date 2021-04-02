import {App, Modal} from "obsidian";

export class TweetErrorModal extends Modal {
    private readonly errorMessage: string;

    constructor(app: App, errorMessage: string) {
        super(app);
        this.errorMessage = errorMessage;
    }

    onOpen() {
        let {contentEl} = this;

        contentEl.setText(`Post failed: ${this.errorMessage}`)
    }

    onClose() {
        let {contentEl} = this;
        contentEl.empty();
    }
}