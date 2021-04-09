import { App, Modal, Notice } from "obsidian";
import { TwitterHandler } from "../TwitterHandler";
import { TweetsPostedModal } from "./TweetsPostedModal/TweetsPostedModal";
import { TweetErrorModal } from "./TweetErrorModal";

export class PostTweetModal extends Modal {
  private readonly twitterHandler: TwitterHandler;
  private readonly selectedText: { text: string; thread: boolean };
  private textAreas: HTMLTextAreaElement[] = [];
  private readonly MAX_TWEET_LENGTH: number = 280;
  private readonly helpText: string = `Please read the documentation on the Github repository.
                        Click <a target="_blank" href="https://github.com/chhoumann/notetweet_obsidian">here</a> to go there.
                        There are lots of shortcuts and features to explore 😁`;

  constructor(
    app: App,
    twitterHandler: TwitterHandler,
    selection?: { text: string; thread: boolean }
  ) {
    super(app);
    this.selectedText = selection ?? { text: "", thread: false };
    this.twitterHandler = twitterHandler;
  }

  onOpen() {
    let { contentEl } = this;
    contentEl.addClass("postTweetModal");

    this.addTooltip("Help", this.helpText, contentEl);

    let textZone = contentEl.createDiv();

    try {
      let textArea = this.createTextarea(textZone);

      this.selectedTextHandler(textArea, textZone);

      let addTweetButton = contentEl.createEl("button", { text: "+" });
      addTweetButton.addEventListener("click", () =>
        this.createTextarea(textZone)
      );

      this.createTweetButton(contentEl);
    } catch (e) {
      new Notice(e);
      this.close();
      return;
    }
  }

  private selectedTextHandler(
    textArea: HTMLTextAreaElement,
    textZone: HTMLDivElement
  ) {
    if (this.selectedText.text.length == 0) return false;

    let joinedTextChunks;
    if (this.selectedText.thread == false)
      joinedTextChunks = this.textInputHandler(this.selectedText.text);
    else joinedTextChunks = this.selectedText.text.split("--nt_sep--");

    this.createTweetsWithInput(joinedTextChunks, textArea, textZone);
  }

  private createTweetsWithInput(
    inputStrings: string[],
    currentTextArea: HTMLTextAreaElement,
    textZone: HTMLDivElement
  ) {
    inputStrings.forEach((chunk) => {
      try {
        let tempTextarea =
          currentTextArea.value.trim() == ""
            ? currentTextArea
            : this.createTextarea(textZone);
        tempTextarea.setRangeText(chunk);
        tempTextarea.dispatchEvent(new InputEvent("input"));

        tempTextarea.style.height = tempTextarea.scrollHeight + "px";
      } catch (e) {
        new Notice(e);
        return;
      }
    });
  }

  // Separate lines by linebreaks. Add lines together, separated by linebreak, if they can fit within a tweet.
  // Repeat this until all separated lines are joined into tweets with proper sizes.
  private textInputHandler(str: string) {
    let chunks: string[] = str.split("\n");
    let i = 0,
      joinedTextChunks: string[] = [];
    chunks.forEach((chunk, j) => {
      if (joinedTextChunks[i] == null) joinedTextChunks[i] = "";
      if (
        joinedTextChunks[i].length + chunk.length <=
        this.MAX_TWEET_LENGTH - 1
      ) {
        joinedTextChunks[i] = joinedTextChunks[i] + chunk;
        joinedTextChunks[i] += j == chunks.length - 1 ? "" : "\n";
      } else {
        if (chunk.length > this.MAX_TWEET_LENGTH) {
          let x = chunk.split(/[.?!]\s/).join("\n");
          this.textInputHandler(x).forEach(
            (split) => (joinedTextChunks[++i] = split)
          );
        } else {
          joinedTextChunks[++i] = chunk;
        }
      }
    });
    return joinedTextChunks;
  }

  onClose() {
    let { contentEl } = this;
    contentEl.empty();
  }

  private createTextarea(textZone: HTMLDivElement) {
    if (this.textAreas.find((ele) => ele.textLength == 0)) {
      throw new Error(
        "You cannot add a new tweet when there are empty tweets."
      );
    }

    let textarea = textZone.createEl("textarea");
    this.textAreas.push(textarea);
    textarea.addClass("tweetArea");

    let lengthCheckerEl = textZone.createEl("p", {
      text: "0 / 280 characters.",
    });
    lengthCheckerEl.addClass("ntLengthChecker");

    textarea.addEventListener("input", () =>
      this.onTweetLengthHandler(textarea.textLength, lengthCheckerEl)
    );
    textarea.addEventListener(
      "keydown",
      this.onInput(textarea, textZone, lengthCheckerEl)
    );
    textarea.addEventListener(
      "paste",
      this.onPasteMaxLengthHandler(textarea, textZone)
    );

    textarea.focus();
    return textarea;
  }

  private addTooltip(title: string, body: string, root: HTMLElement) {
    let tooltip = root.createEl("div", { text: title });
    let tooltipBody = tooltip.createEl("span");
    tooltipBody.innerHTML = body;

    tooltip.addClass("tweetTooltip");
    tooltipBody.addClass("tweetTooltipBody");
  }

  private onPasteMaxLengthHandler(
    textarea: HTMLTextAreaElement,
    textZone: HTMLDivElement
  ) {
    return (event: any) => {
      let pasted: string = event.clipboardData.getData("text");
      if (pasted.length + textarea.textLength > this.MAX_TWEET_LENGTH) {
        event.preventDefault();
        let splicedPaste = this.textInputHandler(pasted);
        this.createTweetsWithInput(splicedPaste, textarea, textZone);
      }
    };
  }

  private onInput(
    textarea: HTMLTextAreaElement,
    textZone: HTMLDivElement,
    lengthCheckerEl: HTMLElement
  ) {
    return (key: any) => {
      if (
        key.code == "Backspace" &&
        textarea.textLength == 0 &&
        this.textAreas.length > 1
      ) {
        key.preventDefault();
        this.deleteTweet(textarea, textZone, lengthCheckerEl);
      }

      if (key.code == "Enter" && textarea.textLength >= this.MAX_TWEET_LENGTH) {
        key.preventDefault();
        try {
          this.createTextarea(textZone);
        } catch (e) {
          new Notice(e);
          return;
        }
      }

      if ((key.code == "Enter" || key.code == "NumpadEnter") && key.altKey) {
        key.preventDefault();
        try {
          this.createTextarea(textZone);
        } catch (e) {
          new Notice(e);
          return;
        }
      }

      if (key.code == "Enter" && key.shiftKey) {
        key.preventDefault();
        this.insertTweetAbove(textarea, textZone);
      }

      if (key.code == "Enter" && key.ctrlKey) {
        key.preventDefault();
        this.insertTweetBelow(textarea, textZone);
      }

      if (key.code == "ArrowUp" && key.ctrlKey && !key.shiftKey) {
        let currentTweetIndex = this.textAreas.findIndex(
          (tweet) => tweet.value == textarea.value
        );
        if (currentTweetIndex > 0)
          this.textAreas[currentTweetIndex - 1].focus();
      }

      if (key.code == "ArrowDown" && key.ctrlKey && !key.shiftKey) {
        let currentTweetIndex = this.textAreas.findIndex(
          (tweet) => tweet.value == textarea.value
        );
        if (currentTweetIndex < this.textAreas.length - 1)
          this.textAreas[currentTweetIndex + 1].focus();
      }

      if (key.code == "ArrowDown" && key.ctrlKey && key.shiftKey) {
        let tweetIndex = this.textAreas.findIndex(
          (ta) => ta.value == textarea.value
        );
        if (tweetIndex != this.textAreas.length - 1) {
          key.preventDefault();
          this.switchTweets(textarea, this.textAreas[tweetIndex + 1]);
          this.textAreas[tweetIndex + 1].focus();
        }
      }

      if (key.code == "ArrowUp" && key.ctrlKey && key.shiftKey) {
        let tweetIndex = this.textAreas.findIndex(
          (ta) => ta.value == textarea.value
        );
        if (tweetIndex != 0) {
          key.preventDefault();
          this.switchTweets(textarea, this.textAreas[tweetIndex - 1]);
          this.textAreas[tweetIndex - 1].focus();
        }
      }

      if (key.code == "Delete" && key.ctrlKey && key.shiftKey) {
        key.preventDefault();
        if (this.textAreas.length == 1) textarea.value = "";
        else this.deleteTweet(textarea, textZone, lengthCheckerEl);
      }

      textarea.style.height = "auto";
      textarea.style.height = textarea.scrollHeight + "px";
    };
  }

  private switchTweets(
    textarea1: HTMLTextAreaElement,
    textarea2: HTMLTextAreaElement
  ) {
    let temp: string = textarea1.value;
    textarea1.value = textarea2.value;
    textarea2.value = temp;
    textarea1.dispatchEvent(new InputEvent("input"));
    textarea2.dispatchEvent(new InputEvent("input"));
  }

  private deleteTweet(
    textarea: HTMLTextAreaElement,
    textZone: HTMLDivElement,
    lengthCheckerEl: HTMLElement
  ) {
    let i = this.textAreas.findIndex((ele) => ele === textarea);
    this.textAreas.remove(textarea);
    textZone.removeChild(textarea);
    textZone.removeChild(lengthCheckerEl);
    this.textAreas[i == 0 ? i : i - 1].focus();
  }

  private onTweetLengthHandler(strlen: Number, lengthCheckerEl: HTMLElement) {
    const WARN1: number = this.MAX_TWEET_LENGTH - 50;
    const WARN2: number = this.MAX_TWEET_LENGTH - 25;
    const DEFAULT_COLOR = "#339900";

    lengthCheckerEl.innerText = `${strlen} / 280 characters.`;

    if (strlen <= WARN1) lengthCheckerEl.style.color = DEFAULT_COLOR;
    if (strlen > WARN1) lengthCheckerEl.style.color = "#ffcc00";
    if (strlen > WARN2) lengthCheckerEl.style.color = "#ff9966";
    if (strlen >= this.MAX_TWEET_LENGTH) {
      lengthCheckerEl.style.color = "#cc3300";
    }
  }

  private createTweetButton(contentEl: HTMLElement) {
    let postButton = contentEl.createEl("button", { text: "Post!" });
    postButton.addClass("postTweetButton");

    postButton.addEventListener("click", this.postTweets());
  }

  private postTweets() {
    return async () => {
      let threadContent = this.textAreas.map((textarea) => textarea.value);

      if (
        threadContent.find(
          (txt) => txt.length > this.MAX_TWEET_LENGTH || txt == ""
        ) != null
      ) {
        new Notice("At least one of your tweets is too long or empty.");
        return;
      }

      try {
        let postedTweets = await this.twitterHandler.postThread(threadContent);
        let postedModal = new TweetsPostedModal(
          this.app,
          postedTweets,
          this.twitterHandler
        );
        postedModal.open();
      } catch (e) {
        new TweetErrorModal(this.app, e.data || e).open();
      }

      this.close();
    };
  }

  private insertTweetAbove(
    textarea: HTMLTextAreaElement,
    textZone: HTMLDivElement
  ) {
    let insertAboveIndex = this.textAreas.findIndex(
      (area) => area.value == textarea.value
    );

    try {
      let insertedTweet = this.createTextarea(textZone);
      this.shiftTweetsDownFromIndex(insertAboveIndex);

      return { tweet: insertedTweet, index: insertAboveIndex };
    } catch (e) {
      new Notice(e);
      return;
    }
  }

  private insertTweetBelow(
    textarea: HTMLTextAreaElement,
    textZone: HTMLDivElement
  ) {
    let insertBelowIndex = this.textAreas.findIndex(
      (area) => area.value == textarea.value
    );
    let fromIndex = insertBelowIndex + 1;

    try {
      let insertedTextarea = this.createTextarea(textZone);
      this.shiftTweetsDownFromIndex(fromIndex);

      return insertedTextarea;
    } catch (e) {
      new Notice(e);
    }
  }

  private shiftTweetsDownFromIndex(insertedIndex: number) {
    for (let i = this.textAreas.length - 1; i > insertedIndex; i--) {
      this.textAreas[i].value = this.textAreas[i - 1].value;
      this.textAreas[i].dispatchEvent(new InputEvent("input"));
    }

    this.textAreas[insertedIndex].value = "";
    this.textAreas[insertedIndex].focus();
  }

  /*    private insertTweetBelowWithText(textarea: HTMLTextAreaElement, textZone: HTMLDivElement, insertText: string){
        // Insert tweet, assign to var. Pass that var in again.
        // It'll be reverse order if I don't insert below each one. For inserting above, you can just insert as you normally would.
        if (insertText.length > this.MAX_TWEET_LENGTH) {
            let sliced = this.textInputHandler(insertText); // First, make sure the text is sized correctly.
            let tweet: HTMLTextAreaElement = textarea;

            let tweetIndex = this.insertTweetBelow(tweet, textZone);
            tweet = this.textAreas[tweetIndex];
            this.insertTweetBelowWithText(tweet, textZone, sliced.slice(1).join());

            // sliced.forEach(chunk => {
            //     console.log("!!!!")
            //     let x = this.insertTweetBelow(tweet, textZone);
            //     tweet = x.insertedTweet;
            //     tweet.value = chunk;
            // });
        }
        else {
            let {insertedTweet, insertedIndex} = this.insertTweetBelow(textarea, textZone);
            this.textAreas[insertedIndex].value = insertText;
        }
    }*/
}
