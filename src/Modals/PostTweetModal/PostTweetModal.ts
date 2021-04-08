import { App, Modal, Notice } from "obsidian";
import { TwitterHandler } from "../../TwitterHandler";
import { TweetsPostedModal } from "../TweetsPostedModal/TweetsPostedModal";
import { TweetErrorModal } from "../TweetErrorModal/TweetErrorModal";
import PostTweetModalContent from "./PostTweetModalContent.svelte";
import { tweetStore } from "../Stores";

export class PostTweetModal extends Modal {
  private readonly twitterHandler: TwitterHandler;
  private readonly MAX_TWEET_LENGTH: number = 280;
  private drafting: boolean;

  private modalContent: PostTweetModalContent;
  private tweets: string[];

  constructor(
    app: App,
    twitterHandler: TwitterHandler,
    drafting: boolean,
    selection?: { text: string; thread: boolean }
  ) {
    super(app);
    this.twitterHandler = twitterHandler;
    this.drafting = drafting;

    tweetStore.subscribe((value) => (this.tweets = value));

    this.modalContent = new PostTweetModalContent({
      target: this.contentEl,
      props: {
        onAddTweet: (pos?: number) => this.addEmptyTweet(pos),
        drafting: this.drafting,
      },
    });

    if (selection) this.selectedTextHandler(selection);
    if (
      (this.tweets.length <= 1 && this.tweets[0] == "") ||
      this.tweets.length == 0
    )
      this.addEmptyTweet();

    this.open();
  }

  private selectedTextHandler(selection: { text: string; thread: boolean }) {
    if (selection.text.length == 0) return false;

    let joinedTextChunks;
    if (selection.thread == false)
      joinedTextChunks = this.textInputHandler(selection.text);
    else joinedTextChunks = selection.text.split("--nt_sep--");

    this.createTweetsWithInput(joinedTextChunks, 0);
  }

  private createTweetsWithInput(inputStrings: string[], position: number) {
    this.tweets.splice(position, 0, ...inputStrings);
    tweetStore.set(this.tweets);

    // inputStrings.forEach((chunk) => {
    //   try {
    //     let tempTextarea =
    //       currentTextArea.value.trim() == ""
    //         ? currentTextArea
    //         : this.addEmptyTweet();
    //     tempTextarea.setRangeText(chunk);
    //     tempTextarea.dispatchEvent(new InputEvent("input"));
    //
    //     tempTextarea.style.height = tempTextarea.scrollHeight + "px";
    //   } catch (e) {
    //     new Notice(e);
    //     return;
    //   }
    // });
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

  private setDrafting(value: boolean) {
    this.drafting = value;
  }

  onClose() {
    super.onClose();
    this.modalContent.$destroy();
    if (!this.drafting) tweetStore.set([]);
  }

  private addEmptyTweet(pos?: number) {
    if (this.tweets.find((tweet) => tweet.length == 0)) {
      throw new Error(
        "You cannot add a new tweet when there are empty tweets."
      );
    }

    if (pos == null) this.tweets.push("");
    else this.tweets.splice(pos, 0, "");

    tweetStore.set(this.tweets);

    // let textarea = textZone.createEl("textarea");
    // this.tweets.push(textarea);
    // textarea.addClass("tweetArea");
    //
    // let lengthCheckerEl = textZone.createEl("p", {
    //   text: "0 / 280 characters.",
    // });
    // lengthCheckerEl.addClass("ntLengthChecker");
    //
    // textarea.addEventListener("input", () =>
    //   this.onTweetLengthHandler(textarea.textLength, lengthCheckerEl)
    // );
    // textarea.addEventListener(
    //   "keydown",
    //   this.onInput(textarea, textZone, lengthCheckerEl)
    // );
    // textarea.addEventListener(
    //   "paste",
    //   this.onPasteMaxLengthHandler(textarea, textZone)
    // );
    //
    // textarea.focus();
    // return textarea;
  }

  // private onPasteMaxLengthHandler(
  //   textarea: HTMLTextAreaElement,
  //   textZone: HTMLDivElement
  // ) {
  //   return (event: any) => {
  //     let pasted: string = event.clipboardData.getData("text");
  //     if (pasted.length + textarea.textLength > this.MAX_TWEET_LENGTH) {
  //       event.preventDefault();
  //       let splicedPaste = this.textInputHandler(pasted);
  //       this.createTweetsWithInput(splicedPaste, textarea, textZone);
  //     }
  //   };
  // }

  // private onInput(
  //   textarea: HTMLTextAreaElement,
  //   textZone: HTMLDivElement,
  //   lengthCheckerEl: HTMLElement
  // ) {
  //   return (key: any) => {
  //     if (
  //       key.code == "Backspace" &&
  //       textarea.textLength == 0 &&
  //       this.textAreas.length > 1
  //     ) {
  //       key.preventDefault();
  //       this.deleteTweet(textarea, textZone, lengthCheckerEl);
  //     }
  //
  //     if (key.code == "Enter" && textarea.textLength >= this.MAX_TWEET_LENGTH) {
  //       key.preventDefault();
  //       try {
  //         this.createTextarea(textZone);
  //       } catch (e) {
  //         new Notice(e);
  //         return;
  //       }
  //     }
  //
  //     if ((key.code == "Enter" || key.code == "NumpadEnter") && key.altKey) {
  //       key.preventDefault();
  //       try {
  //         this.createTextarea(textZone);
  //       } catch (e) {
  //         new Notice(e);
  //         return;
  //       }
  //     }
  //
  //     if (key.code == "Enter" && key.shiftKey) {
  //       key.preventDefault();
  //       this.insertTweetAbove(textarea, textZone);
  //     }
  //
  //     if (key.code == "Enter" && key.ctrlKey) {
  //       key.preventDefault();
  //       this.insertTweetBelow(textarea, textZone);
  //     }
  //
  //     if (key.code == "ArrowUp" && key.ctrlKey && !key.shiftKey) {
  //       let currentTweetIndex = this.textAreas.findIndex(
  //         (tweet) => tweet.value == textarea.value
  //       );
  //       if (currentTweetIndex > 0)
  //         this.textAreas[currentTweetIndex - 1].focus();
  //     }
  //
  //     if (key.code == "ArrowDown" && key.ctrlKey && !key.shiftKey) {
  //       let currentTweetIndex = this.textAreas.findIndex(
  //         (tweet) => tweet.value == textarea.value
  //       );
  //       if (currentTweetIndex < this.textAreas.length - 1)
  //         this.textAreas[currentTweetIndex + 1].focus();
  //     }
  //
  //     if (key.code == "ArrowDown" && key.ctrlKey && key.shiftKey) {
  //       let tweetIndex = this.textAreas.findIndex(
  //         (ta) => ta.value == textarea.value
  //       );
  //       if (tweetIndex != this.textAreas.length - 1) {
  //         key.preventDefault();
  //         this.switchTweets(textarea, this.textAreas[tweetIndex + 1]);
  //         this.textAreas[tweetIndex + 1].focus();
  //       }
  //     }
  //
  //     if (key.code == "ArrowUp" && key.ctrlKey && key.shiftKey) {
  //       let tweetIndex = this.textAreas.findIndex(
  //         (ta) => ta.value == textarea.value
  //       );
  //       if (tweetIndex != 0) {
  //         key.preventDefault();
  //         this.switchTweets(textarea, this.textAreas[tweetIndex - 1]);
  //         this.textAreas[tweetIndex - 1].focus();
  //       }
  //     }
  //
  //     if (key.code == "Delete" && key.ctrlKey && key.shiftKey) {
  //       key.preventDefault();
  //       if (this.textAreas.length == 1) textarea.value = "";
  //       else this.deleteTweet(textarea, textZone, lengthCheckerEl);
  //     }
  //
  //     textarea.style.height = "auto";
  //     textarea.style.height = textarea.scrollHeight + "px";
  //   };
  // }

  private switchStrings(
    string1: string,
    string2: string
  ): { string1: string; string2: string } {
    let temp: string = string1;
    string1 = string2;
    string2 = temp;

    return { string1, string2 };
  }

  // private deleteTweet(
  //   textarea: HTMLTextAreaElement,
  //   textZone: HTMLDivElement,
  //   lengthCheckerEl: HTMLElement
  // ) {
  //   let i = this.textAreas.findIndex((ele) => ele === textarea);
  //   this.textAreas.remove(textarea);
  //   textZone.removeChild(textarea);
  //   textZone.removeChild(lengthCheckerEl);
  //   this.textAreas[i == 0 ? i : i - 1].focus();
  // }

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

  // private postTweets() {
  //   return async () => {
  //     let threadContent = this.textAreas.map((textarea) => textarea.value);
  //
  //     if (
  //       threadContent.find(
  //         (txt) => txt.length > this.MAX_TWEET_LENGTH || txt == ""
  //       ) != null
  //     ) {
  //       new Notice("At least one of your tweets is too long or empty.");
  //       return;
  //     }
  //
  //     try {
  //       let postedTweets = await this.twitterHandler.postThread(threadContent);
  //       let postedModal = new TweetsPostedModal(
  //         this.app,
  //         postedTweets,
  //         this.twitterHandler
  //       );
  //       postedModal.open();
  //     } catch (e) {
  //       new TweetErrorModal(this.app, e.data || e).open();
  //     }
  //
  //     this.close();
  //   };
  // }

  // private insertTweetAbove(
  //   textarea: HTMLTextAreaElement,
  //   textZone: HTMLDivElement
  // ) {
  //   let insertAboveIndex = this.textAreas.findIndex(
  //     (area) => area.value == textarea.value
  //   );
  //
  //   try {
  //     let insertedTweet = this.createTextarea(textZone);
  //     this.shiftTweetsDownFromIndex(insertAboveIndex);
  //
  //     return { tweet: insertedTweet, index: insertAboveIndex };
  //   } catch (e) {
  //     new Notice(e);
  //     return;
  //   }
  // }

  // private insertTweetBelow(
  //   textarea: HTMLTextAreaElement,
  //   textZone: HTMLDivElement
  // ) {
  //   let insertBelowIndex = this.textAreas.findIndex(
  //     (area) => area.value == textarea.value
  //   );
  //   let fromIndex = insertBelowIndex + 1;
  //
  //   try {
  //     let insertedTextarea = this.createTextarea(textZone);
  //     this.shiftTweetsDownFromIndex(fromIndex);
  //
  //     return insertedTextarea;
  //   } catch (e) {
  //     new Notice(e);
  //   }
  // }

  // private shiftTweetsDownFromIndex(insertedIndex: number) {
  //   for (let i = this.textAreas.length - 1; i > insertedIndex; i--) {
  //     this.textAreas[i].value = this.textAreas[i - 1].value;
  //     this.textAreas[i].dispatchEvent(new InputEvent("input"));
  //   }
  //
  //   this.textAreas[insertedIndex].value = "";
  //   this.textAreas[insertedIndex].focus();
  // }
}
