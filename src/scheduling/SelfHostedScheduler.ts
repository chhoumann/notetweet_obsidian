import {ITweet} from "../Types/ITweet";
import {NoteTweetScheduler} from "./NoteTweetScheduler";
import got from 'got';
import {log} from "../ErrorModule/logManager";
import {IScheduledTweet} from "../Types/IScheduledTweet";
import {App} from "obsidian";
import GenericInputPrompt from "../Modals/GenericInputPrompt";

export class SelfHostedScheduler extends NoteTweetScheduler {
    constructor(private app: App, private url: string, private password: string) {
        super();
    }

    async deleteScheduledTweet(tweet: ITweet): Promise<void> {
        const res = await got.delete(`${this.url}/deleteScheduled`, {
            password: this.password,
            json: {
                tweet
            }
        });

        log.logMessage(`Unscheduled tweet: ${tweet.id}.`);
    }

    async getScheduledTweets(): Promise<IScheduledTweet[]> {
        const res = await got.get(`${this.url}/scheduledTweets`, {
            password: this.password
        });

        return JSON.parse(res.body);
    }

    async postTweetNow(tweetId: string): Promise<void> {
    }

    async scheduleTweet(tweet: ITweet): Promise<void> {
        const input: string = await GenericInputPrompt.Prompt(this.app, "Schedule tweet");
        // @ts-ignore
        const nld = this.app.plugins.plugins["nldates-obsidian"].parser.chrono.parseDate(input);
        const nldparsed = Date.parse(nld);
        const date = new Date(nldparsed);

        const res = await got.post(`${this.url}/scheduleTweet`, {
            json: {
                tweet,
                postAt: date.getTime()
            },
            password: this.password
        });

        log.logMessage(`Schedule tweet: ${res.body}`);
    }

    async updateSchedule(cronStrings: string[]): Promise<void> {
        const res = await got.post(`${this.url}/addCronStrings`, {
            json: {
                cronStrings
            },
            password: this.password
        });

        log.logMessage(`Update schedule: ${res.body}`);
    }
}