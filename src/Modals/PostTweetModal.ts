import {App, Modal, Notice} from "obsidian";
import {TwitterHandler} from "../TwitterHandler";
import {TweetsPostedModal} from "./TweetsPostedModal";
import {TweetErrorModal} from "./TweetErrorModal";

export class PostTweetModal extends Modal {
    private readonly twitterHandler: TwitterHandler;
    private readonly selectedText: { text: string; thread: boolean };
    private textAreas: HTMLTextAreaElement[] = [];
    private readonly MAX_TWEET_LENGTH: number = 280;
    private readonly helpText: string = `Please read the documentation on the Github repository.
                        Click <a target="_blank" href="https://github.com/chhoumann/notetweet_obsidian">here</a> to go there.
                        There are lots of shortcuts and features to explore 😁`


    constructor(app: App, twitterHandler: TwitterHandler, selection?: { text: string; thread: boolean }) {
        super(app);
        this.selectedText = selection ?? {text: "", thread: false};
        this.twitterHandler = twitterHandler;
    }

    onOpen() {
        let {contentEl} = this;
        contentEl.addClass("postTweetModal");

        this.addTooltip("Help", this.helpText, contentEl);

        let textZone = contentEl.createDiv();

        let textArea = this.createTextarea(textZone);
        this.selectedTextHandler(textArea, textZone)

        let addTweetButton = contentEl.createEl("button", {text: "+"});
        addTweetButton.addEventListener("click", () => this.createTextarea(textZone));

        this.createTweetButton(contentEl);
    }

    private selectedTextHandler(textArea: HTMLTextAreaElement, textZone: HTMLDivElement) {
        if (this.selectedText.text.length == 0) return false;

        let joinedTextChunks;
        if (this.selectedText.thread == false)
            joinedTextChunks = this.textInputHandler(this.selectedText.text);
        else
            joinedTextChunks = this.selectedText.text.split("--nt_sep--");

        this.createTweetsWithInput(joinedTextChunks, textArea, textZone);
    }

    private createTweetsWithInput(inputStrings: string[], currentTextArea: HTMLTextAreaElement, textZone: HTMLDivElement) {
        inputStrings.forEach(chunk => {
            let tempTextarea = currentTextArea.value.trim() == "" ? currentTextArea : this.createTextarea(textZone);

            tempTextarea.setRangeText(chunk);
            tempTextarea.dispatchEvent(
                new InputEvent('input')
            );

            tempTextarea.style.height = (tempTextarea.scrollHeight) + "px";
        });
    }

    // Separate lines by linebreaks. Add lines together, separated by linebreak, if they can fit within a tweet.
    // Repeat this until all separated lines are joined into tweets with proper sizes.
    private textInputHandler(str: string) {
        let chunks: string[] = str.split("\n");
        let i = 0, joinedTextChunks: string[] = [];
        chunks.forEach(chunk => {
            if (joinedTextChunks[i] == null) joinedTextChunks[i] = "";
            if (joinedTextChunks[i].length + chunk.length <= this.MAX_TWEET_LENGTH - 1) {
                joinedTextChunks[i] = joinedTextChunks[i] + chunk.trim() + "\n";
            } else i++;
        })
        return joinedTextChunks;
    }

    onClose() {
        let {contentEl} = this;
        contentEl.empty();
    }

    private createTextarea(textZone: HTMLDivElement) {
        if (this.textAreas.find(ele => ele.textLength == 0)) {
            new Notice("You cannot add a new tweet when there are empty tweets.")
            return;
        }

        let textarea = textZone.createEl("textarea");
        this.textAreas.push(textarea);
        textarea.addClass("tweetArea")

        let lengthCheckerEl = textZone.createEl("p", {text: "0 / 280 characters."});
        lengthCheckerEl.addClass("ntLengthChecker")

        textarea.addEventListener("input", () => this.onTweetLengthHandler(textarea.textLength, lengthCheckerEl));
        textarea.addEventListener("keydown", this.onInput(textarea, textZone, lengthCheckerEl))
        textarea.addEventListener("paste", this.onPasteMaxLengthHandler(textarea, textZone))

        textarea.focus();
        return textarea;
    }

    private addTooltip(title: string, body: string, root: HTMLElement) {
        let tooltip = root.createEl("div", {text: title});
        let tooltipBody = tooltip.createEl("span");
        tooltipBody.innerHTML = body;

        tooltip.addClass("tweetTooltip");
        tooltipBody.addClass("tweetTooltipBody");
    }

    private onPasteMaxLengthHandler(textarea: HTMLTextAreaElement, textZone: HTMLDivElement) {
        return (event: any) => {
            let pasted: string = event.clipboardData.getData("text");
            if (pasted.length + textarea.textLength > this.MAX_TWEET_LENGTH) {
                event.preventDefault();
                this.createTweetsWithInput(this.textInputHandler(pasted), textarea, textZone);
            }
        };
    }

    private onInput(textarea: HTMLTextAreaElement, textZone: HTMLDivElement, lengthCheckerEl: HTMLElement) {
        return (key: any) => {
            this.deleteEmptyTweetOnBackspace(key, textarea, textZone, lengthCheckerEl);
            //this.disallowTextAppendOnMaxLength(textarea, key);
            this.newTweetOnMaxLengthOnEnterPress(key, textarea, textZone);
            this.newTweetOnCtrlEnter(key, textZone);

            textarea.style.height = "auto";
            textarea.style.height = (textarea.scrollHeight) + "px";
        };
    }

    private deleteEmptyTweetOnBackspace(key: any, textarea: HTMLTextAreaElement, textZone: HTMLDivElement, lengthCheckerEl: HTMLElement) {
        if (key.code == "Backspace" && textarea.textLength == 0 && this.textAreas.length > 1) {
            let i = this.textAreas.findIndex(ele => ele === textarea);
            this.textAreas.remove(textarea);
            textZone.removeChild(textarea);
            textZone.removeChild(lengthCheckerEl);
            this.textAreas[i == 0 ? i : i - 1].focus();
            key.preventDefault();
        }
    }

    private disallowTextAppendOnMaxLength(textarea: HTMLTextAreaElement, key: any) {
        if (textarea.textLength >= this.MAX_TWEET_LENGTH && key.code != "Backspace") {
            key.preventDefault();
        }
    }

    private newTweetOnMaxLengthOnEnterPress(key: any, textarea: HTMLTextAreaElement, textZone: HTMLDivElement) {
        if (key.code == "Enter" && textarea.textLength >= this.MAX_TWEET_LENGTH) {
            this.createTextarea(textZone);
        }
    }

    private newTweetOnCtrlEnter(key: any, textZone: HTMLDivElement) {
        if ((key.code == "Enter" || key.code == "NumpadEnter") && key.ctrlKey) {
            this.createTextarea(textZone);
        }
    }

    private onTweetLengthHandler(strlen: Number, lengthCheckerEl: HTMLElement) {
        const WARN1: number = this.MAX_TWEET_LENGTH - 50;
        const WARN2: number = this.MAX_TWEET_LENGTH - 25;
        const DEFAULT_COLOR = "#339900";

        lengthCheckerEl.innerText = `${strlen} / 250 characters.`;

        if (strlen <= WARN1)
            lengthCheckerEl.style.color = DEFAULT_COLOR;
        if (strlen > WARN1)
            lengthCheckerEl.style.color = "#ffcc00";
        if (strlen > WARN2)
            lengthCheckerEl.style.color = "#ff9966";
        if (strlen >= this.MAX_TWEET_LENGTH) {
            lengthCheckerEl.style.color = "#cc3300";
        }
    }

    private createTweetButton(contentEl: HTMLElement) {
        let postButton = contentEl.createEl("button", {text: "Post!"});
        postButton.addClass("postTweetButton");

        postButton.addEventListener("click", this.postTweets());
    }

    private postTweets() {
        return async () => {
            let threadContent = this.textAreas.map(textarea => textarea.value);

            if (threadContent.find(txt => txt.length > this.MAX_TWEET_LENGTH)) {
                new Notice("At least one of your tweets is too long.");
                return;
            }

            try {
                let postedTweets = await this.twitterHandler.postThread(threadContent);
                let postedModal = new TweetsPostedModal(this.app, postedTweets, this.twitterHandler);
                postedModal.open();
            } catch (e) {
                new TweetErrorModal(this.app, e.data || e).open();
            }

            this.close();
        };
    }
}