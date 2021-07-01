import {App, ButtonComponent, Modal} from "obsidian";
import {NoteTweetScheduler} from "../scheduling/NoteTweetScheduler";
import {IScheduledTweet} from "../Types/IScheduledTweet";
import {promptForDateTime} from "../utility";
import {UpdateScheduledTweetModal} from "./UpdateScheduledTweetModal";

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
        const heading = this.contentEl.createEl('h2', {text: `Scheduled tweets (${scheduledTweets?.length ?? 0})`});
        heading.style.marginBottom = "0";

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
            const tweetContainer: HTMLDivElement = rowContainer.createDiv('tweetContainer');
            const tweetItem = tweetContainer.createEl('span');
            tweetItem.innerText = item;
        });

        const tweetPostAt = rowContainer.createEl('p');
        tweetPostAt.textContent = `Scheduled for: ${window.moment(tweet.postat).format("DD-MM-YYYY HH:mm")}`

        const buttonRowContainer: HTMLDivElement = rowContainer.createDiv();
        buttonRowContainer.style.display = "flex";
        buttonRowContainer.style.alignContent = "center";
        buttonRowContainer.style.justifyContent = "space-between";

        const deleteButton: ButtonComponent = new ButtonComponent(buttonRowContainer);
        deleteButton.setButtonText("Delete")
            .onClick(async () => {
                await this.scheduler.deleteScheduledTweet(tweet);
                await this.display();
            });

        const updateScheduledTweetButtonsContainer: HTMLDivElement = buttonRowContainer.createDiv('updateScheduledTweetButtonsContainer');
        const updateScheduledTimeButton: ButtonComponent = new ButtonComponent(updateScheduledTweetButtonsContainer);
        updateScheduledTimeButton.setCta().setButtonText("Update scheduled time")
            .onClick(async () => {
                tweet.postat = await promptForDateTime(this.app);

                await this.scheduler.updateTweet(tweet);
                await this.display();
            });

        const editTweetButton: ButtonComponent = new ButtonComponent(updateScheduledTweetButtonsContainer);
        editTweetButton.setCta().setButtonText("Edit")
            .onClick(async () => {
                const updatedTweet: IScheduledTweet = await UpdateScheduledTweetModal.Update(this.app, tweet);

                await this.scheduler.updateTweet(updatedTweet);
                await this.display();
            })
    }

    async onOpen() {
        super.onOpen();
        await this.display();
    }

}