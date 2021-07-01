import {App, ButtonComponent, Modal, moment} from "obsidian";
import {NoteTweetScheduler} from "../scheduling/NoteTweetScheduler";
import {ITweet} from "../Types/ITweet";
import {IScheduledTweet} from "../Types/IScheduledTweet";
import GenericInputPrompt from "./GenericInputPrompt";

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

        const editButton: ButtonComponent = new ButtonComponent(buttonRowContainer);
        editButton.setCta().setButtonText("Update scheduled time")
            .onClick(async () => {
                const input: string = await GenericInputPrompt.Prompt(this.app, "Update scheduled time");
                // @ts-ignore
                const nld = this.app.plugins.plugins["nldates-obsidian"].parser.chrono.parseDate(input);
                const nldparsed = Date.parse(nld);
                const date = new Date(nldparsed);

                tweet.postat = date.getTime();

                await this.scheduler.updateTweet(tweet);
                await this.display();
            })
    }

    async onOpen() {
        super.onOpen();
        await this.display();
    }

}