import {App, Modal, Notice} from "obsidian";
import {TwitterHandler} from "../TwitterHandler";
import {TweetsPostedModal} from "./TweetsPostedModal";
import {TweetErrorModal} from "./TweetErrorModal";

export class PostTweetModal extends Modal {
    private readonly twitterHandler: TwitterHandler;
    private readonly selectedText: string = "";
    private textAreas: HTMLTextAreaElementElement[] = [];
    private readonly MAX_TWEET_LENGTH: number = 250;


    constructor(app: App, twitterHandler: TwitterHandler, selection: string = "") {
        super(app);
        this.selectedText = selection;
        this.twitterHandler = twitterHandler;
    }

    onOpen() {
        let {contentEl} = this;
        this.formatModal(contentEl);

        contentEl.createEl("p", {text: "Please enter a tweet."})
        let textZone = contentEl.createDiv();

        let textArea = this.createTextarea(textZone);
        this.selectedTextHandler(textArea, textZone)

        let addTweetButton = contentEl.createEl("button", {text: "+"});
        addTweetButton.addEventListener("click", () => this.createTextarea(textZone));

        this.createTweetButton(contentEl);
    }

    private selectedTextHandler(textArea: HTMLTextAreaElement, textZone: HTMLDivElement) {
        if (this.selectedText.length == 0) return false;

        let jc = this.textInputHandler(this.selectedText);

        this.createTweetsWithInput(jc, textArea, textZone);
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

    private textInputHandler(str: string) {
        let chunks: string[] = str.split("\n");
        let i = 0;
        let jc = [];
        chunks.forEach(chunk => {
            if (jc[i] == null) jc[i] = "";
            if (jc[i].length + chunk.length <= this.MAX_TWEET_LENGTH - 1) {
                jc[i] = jc[i] + chunk.trim() + "\n";
            } else i++;
        })
        return jc;
    }

    onClose() {
        let {contentEl} = this;
        contentEl.empty();
    }

    private formatModal(contentEl: HTMLElement) {
        contentEl.style.maxWidth = "35rem";
        contentEl.style.width = "40rem";
        contentEl.style.overflowY = "auto";
        contentEl.style.maxHeight = "50rem";
        contentEl.style.paddingLeft = "0.5rem";
        contentEl.style.paddingRight = "0.5rem";
    }

    private createTextarea(textZone: HTMLDivElement) {
        if (this.textAreas.find(ele => ele.textLength == 0)) {
            new Notice("You cannot add a new tweet when there are empty tweets.")
            return;
        }

        let textarea = textZone.createEl("textarea");
        this.textAreas.push(textarea);
        textarea.style.maxWidth = "35rem";
        textarea.style.width = "100%";
        textarea.style.display = "inline-block";
        textarea.style.minHeight = "7.5rem";
        textarea.style.overflowY = "hidden";

        let lengthCheckerEl = textZone.createEl("p", {text: "0 / 250 characters."});
        lengthCheckerEl.style.marginTop = "0px";
        lengthCheckerEl.style.marginBottom = "5px";

        textarea.addEventListener("input", () => this.onTweetLengthHandler(textarea.textLength, lengthCheckerEl));
        textarea.addEventListener("focusin", this.onTextAreaFocus(textarea));
        textarea.addEventListener("focusout", this.onTextAreaUnfocus(textarea));
        textarea.addEventListener("keydown", this.onInput(textarea, textZone, lengthCheckerEl))
        textarea.addEventListener("paste", this.onPasteMaxLengthHandler(textarea, textZone))

        textarea.focus();
        return textarea;
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

    private onTextAreaUnfocus(textarea: HTMLTextAreaElement) {
        return () => {
            textarea.style.border = "0.0px solid rgba(63,63,63,1)"
        };
    }

    private onTextAreaFocus(textarea: HTMLTextAreaElement) {
        return () => {
            textarea.style.border = "0.5px solid rgba(63,63,63,1)";
        };
    }

    private onTweetLengthHandler(strlen: Number, lengthCheckerEl: HTMLElement) {
        const WARN1: number = this.MAX_TWEET_LENGTH - 50;
        const WARN2: number = this.MAX_TWEET_LENGTH - 25;
        const DEFAULT_COLOR = "rgb(56, 58, 66)";

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

        postButton.style.backgroundColor = "#3ec5e0";
        postButton.style.float = "right";
        postButton.style.marginTop = "1rem";
        postButton.style.width = "120px";
        postButton.style.height = "30px";
        postButton.style.fontSize = "14px";

        postButton.addEventListener("click", this.postTweets());
    }

    private postTweets() {
        return async () => {
            let threadContent = this.textAreas.map(textarea => textarea.value);

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