import {App, ButtonComponent, Modal} from "obsidian";
import {NoteTweetScheduler} from "../scheduling/NoteTweetScheduler";
import {ITweet} from "../Types/ITweet";

export class ScheduledTweetsModal extends Modal {
    private readonly scheduler: NoteTweetScheduler;

    constructor(app: App, scheduler: NoteTweetScheduler) {
        super(app);
        this.scheduler = scheduler;
    }

    private async display(): Promise<void> {
        this.contentEl.empty();
        this.contentEl.addClass('postTweetModal');

        const scheduledTweets: ITweet[] = await this.scheduler.getScheduledTweets();
        this.contentEl.createEl('h2', {text: `Scheduled tweets (${scheduledTweets?.length ?? 0})`});

        if (scheduledTweets.length === 0) {
            this.contentEl.createEl('p', {text: "No scheduled tweets. Go write some! 😁"})
        } else {
            const scheduledTweetsContainer: HTMLDivElement = this.contentEl.createDiv('scheduledTweetsContainer');
            scheduledTweets.forEach(tweet => {
                this.addTweetRow(tweet, scheduledTweetsContainer);
            });
        }
    }

    private addTweetRow(tweet: ITweet, container: HTMLDivElement): void {
        const rowContainer: HTMLDivElement = container.createDiv('scheduledTweet');
        tweet.content.forEach((item, i) => {
            const tweetItem = rowContainer.createEl('p');
            tweetItem.textContent = item;
        });

        const deleteButton: ButtonComponent = new ButtonComponent(rowContainer);
            deleteButton.setButtonText("Delete")
                .onClick(async () => {
                    await this.scheduler.deleteScheduledTweet(tweet);
                    await this.display();
                })
    }

    async onOpen() {
        super.onOpen();
        await this.display();
    }

}