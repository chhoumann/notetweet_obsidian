import {IScheduledTweet} from "../Types/IScheduledTweet";
import {ITweet} from "../Types/ITweet";
import {App} from "obsidian";
import {log} from "../ErrorModule/logManager";
import {Tweet} from "../Types/Tweet";
import {promptForDateTime} from "../utility";
import {ScheduledTweet} from "../Types/ScheduledTweet";
import {PostTweetModal} from "./PostTweetModal";
import NoteTweet from "../main";

export class NewTweetModal extends PostTweetModal<IScheduledTweet | ITweet> {
    static PostTweet(app: App, selection?: { text: string, thread: boolean }): Promise<ITweet | IScheduledTweet> {
        // Get plugin instance
        const plugin = (app as any).plugins.plugins["notetweet"] as NoteTweet;
        const modal = new NewTweetModal(app, plugin, selection);
        modal.open();
        return modal.newTweet;
    }

    constructor(app: App, plugin: NoteTweet, selection?: { text: string, thread: boolean }) {
        super(app, plugin, selection);
    }

    protected addActionButtons() {
        this.createTweetButton(this.contentEl);
        this.createScheduleButton(this.contentEl);
    }

    private createTweetButton(contentEl: HTMLElement) {
        let postButton = contentEl.createEl("button", {text: "Post!"});
        postButton.addClass("postTweetButton");

        postButton.addEventListener("click", this.postTweets());
    }

    private createScheduleButton(contentEl: HTMLElement) {
        const scheduleButton = contentEl.createEl('button', {text: 'Schedule'});
        scheduleButton.addClass("postTweetButton");

        scheduleButton.addEventListener('click', this.scheduleTweets());
    }

    private postTweets() {
        return async () => {
            const threadContent: string[] = this.getThreadContent();
            if (!threadContent) return;

            const tweet: ITweet = new Tweet(threadContent);
            this.resolve(tweet);
            this.close();
        };
    }

    scheduleTweets() {
        return async () => {
            const threadContent: string[] = this.getThreadContent();
            if (!threadContent) return;

            const scheduledDateTime: number = await promptForDateTime(this.app);
            const tweet: IScheduledTweet = new ScheduledTweet(threadContent, scheduledDateTime)
            this.resolve(tweet);
            this.close();
        }
    }
}