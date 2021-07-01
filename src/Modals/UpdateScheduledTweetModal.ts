import {IScheduledTweet} from "../Types/IScheduledTweet";
import {ITweet} from "../Types/ITweet";
import {App} from "obsidian";
import {log} from "../ErrorModule/logManager";
import {Tweet} from "../Types/Tweet";
import {promptForDateTime} from "../utility";
import {ScheduledTweet} from "../Types/ScheduledTweet";
import {PostTweetModal} from "./PostTweetModal";

export class UpdateScheduledTweetModal extends PostTweetModal<IScheduledTweet> {
    static Update(app: App, tweet: IScheduledTweet): Promise<IScheduledTweet> {
        const modal = new UpdateScheduledTweetModal(app, tweet);
        modal.open();
        return modal.newTweet;
    }

    constructor(app: App, private tweet: IScheduledTweet) {
        super(app);
    }

    protected createFirstTextarea() {
        const textarea: HTMLTextAreaElement = this.createTextarea(this.textZone);

        this.createTweetsWithInput(this.tweet.content, textarea, this.textZone);
    }

    protected addActionButtons() {
        this.createScheduleButton(this.contentEl);
    }

    private createScheduleButton(contentEl: HTMLElement) {
        const scheduleButton = contentEl.createEl('button', {text: 'Update'});
        scheduleButton.addClass("postTweetButton");

        scheduleButton.addEventListener('click', this.updateScheduledTweet());
    }

    updateScheduledTweet() {
        return async () => {
            const threadContent: string[] = this.getThreadContent();
            if (!threadContent) return;

            const tweet: IScheduledTweet = {...this.tweet, content: threadContent};
            this.resolve(tweet);
            this.close();
        }
    }
}