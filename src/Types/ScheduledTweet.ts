import {Tweet} from "./Tweet";
import {IScheduledTweet} from "./IScheduledTweet";

export class ScheduledTweet extends Tweet implements IScheduledTweet {
    postat: number;

    constructor(tweets: string[], postat: number) {
        super(tweets);
        this.postat = postat;
    }

}