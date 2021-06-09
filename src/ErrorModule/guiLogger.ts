import {NoteTweetLogger} from "./noteTweetLogger";
import {TweetErrorModal} from "../Modals/TweetErrorModal";
import NoteTweet from "../main";
import {Notice} from "obsidian";

export class GuiLogger extends NoteTweetLogger {
    constructor(private plugin: NoteTweet) {
        super();
    }

    logError(msg: string): void {
        new TweetErrorModal(this.plugin.app, msg).open();
    }

    logWarning(msg: string): void {
        new Notice(msg);
    }

    logMessage(msg: string): void {}
}