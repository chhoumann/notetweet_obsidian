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
  private tweetZone: HTMLDivElement;

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
        onToggleDrafting: (value: boolean) => this.setDrafting(value),
        drafting: this.drafting,
        onTweetShortcut: (key: any, element: HTMLTextAreaElement) =>
          this.shortcutHandler(key, element),
      },
    });

    if (selection) this.selectedTextHandler(selection);
    if ((this.tweets.length <= 1 && this.tweets[0]) || this.tweets.length == 0)
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

  private findTweetIndex(tweet: string): number {
    return this.tweets.findIndex((t) => t == tweet);
  }

  private shortcutHandler(key: any, textarea: HTMLTextAreaElement) {
    // TODO: Unsure
    if (
      key.code == "Backspace" &&
      textarea.textLength == 0 &&
      this.tweets.length > 1
    ) {
      key.preventDefault();
      this.deleteTweet(this.findTweetIndex(textarea.textContent));
    }

    // TODO: Unsure
    if (key.code == "Enter" && textarea.textLength >= this.MAX_TWEET_LENGTH) {
      key.preventDefault();
      try {
        this.addEmptyTweet();
      } catch (e) {
        new Notice(e);
        return;
      }
    }

    if ((key.code == "Enter" || key.code == "NumpadEnter") && key.altKey) {
      key.preventDefault();
      try {
        this.addEmptyTweet();
      } catch (e) {
        new Notice(e);
        return;
      }
    }

    if (key.code == "Enter" && key.shiftKey) {
      key.preventDefault();
      let currentIndex: number = this.findTweetIndex(textarea.value);
      this.insertTweetAbove(currentIndex);
    }

    if (key.code == "Enter" && key.ctrlKey) {
      key.preventDefault();
      this.insertTweetBelow(this.findTweetIndex(textarea.value));
    }

    // if (key.code == "ArrowUp" && key.ctrlKey && !key.shiftKey) {
    //   let currentTweetIndex = this.tweets.findIndex(
    //     (tweet) => tweet == textarea.value
    //   );
    //   if (currentTweetIndex > 0)
    //     this.textAreas[currentTweetIndex - 1].focus();
    // }
    //
    // if (key.code == "ArrowDown" && key.ctrlKey && !key.shiftKey) {
    //   let currentTweetIndex = this.textAreas.findIndex(
    //     (tweet) => tweet.value == textarea.value
    //   );
    //   if (currentTweetIndex < this.textAreas.length - 1)
    //     this.textAreas[currentTweetIndex + 1].focus();
    // }
    //
    // if (key.code == "ArrowDown" && key.ctrlKey && key.shiftKey) {
    //   let tweetIndex = this.textAreas.findIndex(
    //     (ta) => ta.value == textarea.value
    //   );
    //   if (tweetIndex != this.textAreas.length - 1) {
    //     key.preventDefault();
    //     this.switchTweets(textarea, this.textAreas[tweetIndex + 1]);
    //     this.textAreas[tweetIndex + 1].focus();
    //   }
    // }
    //
    // if (key.code == "ArrowUp" && key.ctrlKey && key.shiftKey) {
    //   let tweetIndex = this.textAreas.findIndex(
    //     (ta) => ta.value == textarea.value
    //   );
    //   if (tweetIndex != 0) {
    //     key.preventDefault();
    //     this.switchTweets(textarea, this.textAreas[tweetIndex - 1]);
    //     this.textAreas[tweetIndex - 1].focus();
    //   }
    // }

    if (key.code == "Delete" && key.ctrlKey && key.shiftKey) {
      key.preventDefault();
      if (this.tweets.length == 1) {
        this.tweets[0] = "";
        tweetStore.set(this.tweets);
      } else this.deleteTweet(this.findTweetIndex(textarea.value));
    }
  }

  private switchTweets(index1: number, index2: number) {
    let temp: string = this.tweets[index1];
    this.tweets[index1] = this.tweets[index2];
    this.tweets[index2] = temp;
  }

  private deleteTweet(position: number) {
    this.tweets.splice(position, 1);
    tweetStore.set(this.tweets);
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

  private insertTweetAbove(position: number) {
    try {
      this.addEmptyTweet(position);
      this.switchTweets(position, position + 1);
      tweetStore.set(this.tweets);
    } catch (e) {
      new Notice(e);
      return;
    }
  }

  private insertTweetBelow(position: number) {
    try {
      this.addEmptyTweet(position);
      this.switchTweets(position + 1, position);
      tweetStore.set(this.tweets);
    } catch (e) {
      new Notice(e);
    }
  }
}
