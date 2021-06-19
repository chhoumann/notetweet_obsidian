import {ITweet} from "../Types/ITweet";

export abstract class NoteTweetScheduler {
    public abstract postTweetNow(tweetId: string): Promise<void>;
    public abstract scheduleTweet(tweet: ITweet): Promise<void>;
    public abstract getScheduledTweets(): Promise<ITweet[]>;
    public abstract deleteScheduledTweet(tweet: ITweet): Promise<void>;
    public abstract updateSchedule(cronStrings: string[]): Promise<void>;
}

