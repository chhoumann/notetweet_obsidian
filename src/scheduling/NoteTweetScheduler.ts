import {ITweet} from "../Types/ITweet";
import {IScheduledTweet} from "../Types/IScheduledTweet";

export abstract class NoteTweetScheduler {
    public abstract postTweetNow(tweetId: string): Promise<void>;
    public abstract scheduleTweet(tweet: ITweet): Promise<void>;
    public abstract getScheduledTweets(): Promise<IScheduledTweet[]>;
    public abstract deleteScheduledTweet(tweet: ITweet): Promise<void>;
    public abstract updateTweet(newTweet: IScheduledTweet): Promise<void>;
}

