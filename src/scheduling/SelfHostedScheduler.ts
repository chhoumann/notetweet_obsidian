import {ITweet} from "../Types/ITweet";
import {NoteTweetScheduler} from "./NoteTweetScheduler";
import got from 'got';
import {log} from "../ErrorModule/logManager";
import {IScheduledTweet} from "../Types/IScheduledTweet";
import {App, moment, Notice} from "obsidian";

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

    async scheduleTweet(tweet: IScheduledTweet): Promise<void> {
        const res = await got.post(`${this.url}/scheduleTweet`, {
            json: {
                tweet,
                postAt: tweet.postat
            },
            password: this.password
        });

        log.logMessage(`Schedule tweet: ${res.body}`);
        new Notice(`Scheduled tweet '${tweet.content[0].substr(0, 10)}...' for ${window.moment(new Date(tweet.postat)).format("DD-MM-YY HH:mm")}`);
    }

    async updateTweet(newTweet: IScheduledTweet): Promise<void> {
        const res = await got.post(`${this.url}/updateTweet`, {
            json: {
                tweet: newTweet,
                postAt: newTweet.postat
            },
            password: this.password
        });

        log.logMessage(`Update tweet: ${res.body}`);
    }
}