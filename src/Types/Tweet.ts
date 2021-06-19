import {v4 as uuidv4} from "uuid";
import {ITweet} from "./ITweet";

export class Tweet implements ITweet {
    id: string;
    content: string[];

    constructor(tweet: string[]) {
        this.content = tweet;
        this.id = uuidv4();
    }
}