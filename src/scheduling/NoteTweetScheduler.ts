import {ITweet} from "../Types/ITweet";
import {IScheduledTweet} from "../Types/IScheduledTweet";

export abstract class NoteTweetScheduler {
    public abstract scheduleTweet(tweet: IScheduledTweet): Promise<void>;
    public abstract getScheduledTweets(): Promise<IScheduledTweet[]>;
    public abstract deleteScheduledTweet(tweet: ITweet): Promise<void>;
    public abstract updateTweet(newTweet: IScheduledTweet): Promise<void>;
}

