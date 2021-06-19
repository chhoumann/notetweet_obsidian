import {ITweet} from "../Types/ITweet";
import {NoteTweetScheduler} from "./NoteTweetScheduler";
import got from 'got';
import {Tweet} from "../Types/Tweet";
import {log} from "../ErrorModule/logManager";

export class SelfHostedScheduler extends NoteTweetScheduler {
    constructor(private url: string, private password: string) {
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

    async getScheduledTweets(): Promise<ITweet[]> {
        const res = await got.get(`${this.url}/scheduledTweets`, {
            password: this.password
        });

        return JSON.parse(res.body).tweets;
    }

    async postTweetNow(tweetId: string): Promise<void> {
    }

    async scheduleTweet(tweet: ITweet): Promise<void> {
        const res = await got.post(`${this.url}/scheduleTweet`, {
            json: {
                tweet
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