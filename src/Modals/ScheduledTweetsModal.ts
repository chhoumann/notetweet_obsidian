import {App, ButtonComponent, Modal, moment} from "obsidian";
import {NoteTweetScheduler} from "../scheduling/NoteTweetScheduler";
import {ITweet} from "../Types/ITweet";
import {IScheduledTweet} from "../Types/IScheduledTweet";

export class ScheduledTweetsModal extends Modal {
    private readonly scheduler: NoteTweetScheduler;

    constructor(app: App, scheduler: NoteTweetScheduler) {
        super(app);
        this.scheduler = scheduler;
    }

    private async display(): Promise<void> {
        this.contentEl.empty();
        this.contentEl.addClass('postTweetModal');

        const scheduledTweets: IScheduledTweet[] = await this.scheduler.getScheduledTweets();
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

    private addTweetRow(tweet: IScheduledTweet, container: HTMLDivElement): void {
        const rowContainer: HTMLDivElement = container.createDiv('scheduledTweet');
        tweet.content.forEach((item, i) => {
            const tweetItem = rowContainer.createEl('p');
            tweetItem.innerHTML = item;
        });

        const tweetPostAt = rowContainer.createEl('p');
        tweetPostAt.textContent = `Scheduled for: ${window.moment(tweet.postat).format("DD-MM-YYYY HH:mm")}`
        console.log(tweet.postat);

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