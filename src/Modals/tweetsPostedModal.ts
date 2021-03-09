import {App, Modal, Notice} from "obsidian";
import {StatusesUpdate} from "twitter-api-client";
import {TwitterHandler} from "../TwitterHandler";
import {ok} from "assert";

export class TweetsPostedModal extends Modal {
    private readonly posts: StatusesUpdate[];
    private readonly twitterHandler: TwitterHandler;

    constructor(app: App, post: StatusesUpdate[], twitterHandler: TwitterHandler) {
        super(app);
        this.posts = post;
        this.twitterHandler = twitterHandler;
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

        this.createButtons(contentEl);
    }

    private createButtons(contentEl: HTMLElement) {
        this.createOkButton(contentEl);
        this.createDeleteButton(contentEl);
    }

    private createDeleteButton(contentEl: HTMLElement) {
        let deleteButton = contentEl.createEl("button", {text: `Delete${this.posts.length == 1 ? "" : " all"}!`});

        deleteButton.style.backgroundColor = "#ff4b4b";
        deleteButton.style.color = "white";
        deleteButton.style.float = "right";
        deleteButton.style.margin = "1rem";
        deleteButton.style.textDecoration = "bold";

        deleteButton.addEventListener("click", async () => {
            let didDeleteTweets = await this.twitterHandler.deleteTweets(this.posts);

            if (didDeleteTweets) {
                this.close();
                new Notice(`${this.posts.length} tweets deleted.`);
            }
            else
                new Notice(`Could not delete tweet(s)`);
        });
    }

    private createOkButton(contentEl: HTMLElement) {
        let okButton = contentEl.createEl("button", {text: "Great!"});

        okButton.style.backgroundColor = "#4BB543";
        okButton.style.float = "right";
        okButton.style.marginTop = "1rem";
        okButton.style.color = "white";

        okButton.addEventListener("click", () => this.close());
    }

    onClose() {
        let {contentEl} = this;
        contentEl.empty();
    }
}