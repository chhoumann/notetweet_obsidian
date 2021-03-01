import {App, Modal} from "obsidian";
import {StatusesUpdate} from "twitter-api-client";

export class TweetPostedModal extends Modal {
    private readonly post: StatusesUpdate;

    constructor(app: App, post: any) {
        super(app);
        this.post = post;
    }

    onOpen() {
        let {contentEl} = this;

        contentEl.createEl("p", {
            text: "Your tweet is live! Check it out here:"
        });
        contentEl.createEl("a", {
            href: `https://twitter.com/${this.post.user.screen_name}/status/${this.post.id_str}`,
        }).innerHTML = this.post.text;
    }

    onClose() {
        let {contentEl} = this;
        contentEl.empty();
    }
}