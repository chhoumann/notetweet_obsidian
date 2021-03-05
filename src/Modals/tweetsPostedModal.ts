import {App, Modal} from "obsidian";
import {StatusesUpdate} from "twitter-api-client";

export class TweetsPostedModal extends Modal {
    private readonly posts: StatusesUpdate[];

    constructor(app: App, post: StatusesUpdate[]) {
        super(app);
        this.posts = post;
    }

    onOpen() {
        let {contentEl} = this;

        contentEl.createEl("h2", {
            text: `Your tweet${this.posts.length > 1 ? "s are" : " is "} live! Check it out here:`
        });

        this.posts.forEach(tweet => {
            contentEl.createEl("a", {
                href: `https://twitter.com/${tweet.user.screen_name}/status/${tweet.id_str}`,
            }).innerHTML = tweet.text;
            contentEl.createEl("br").createEl("br");
        })
    }

    onClose() {
        let {contentEl} = this;
        contentEl.empty();
    }
}