import { App, Modal, Notice } from "obsidian";
import { StatusesUpdate } from "twitter-api-client";
import { TwitterHandler } from "../../TwitterHandler";
import TweetsPostedModalContent from "./TweetsPostedModalContent.svelte";

export class TweetsPostedModal extends Modal {
  private readonly posts: StatusesUpdate[];
  private readonly twitterHandler: TwitterHandler;
  private modalContent: TweetsPostedModalContent;
  private resolvePromise: () => void;
  public waitForClose: Promise<void>;
  public userDeletedTweets: boolean = false;

  constructor(
    app: App,
    post: StatusesUpdate[],
    twitterHandler: TwitterHandler
  ) {
    super(app);
    this.posts = post;
    this.twitterHandler = twitterHandler;
    this.waitForClose = new Promise<void>(
      (resolve) => (this.resolvePromise = resolve)
    );

    this.modalContent = new TweetsPostedModalContent({
      target: this.contentEl,
      props: {
        posts: this.posts,
        onDelete: this.deleteTweets(),
        onAccept: () => this.close(),
      },
    });

    this.open();
  }

  private deleteTweets() {
    return async () => {
      let didDeleteTweets = await this.twitterHandler.deleteTweets(this.posts);

      if (didDeleteTweets) {
        this.userDeletedTweets = true;
        this.close();
        new Notice(
          `${this.posts.length} tweet${
            this.posts.length > 1 ? "s" : ""
          } deleted.`
        );
      } else new Notice(`Could not delete tweet(s)`);
    };
  }

  onClose() {
    super.onClose();
    this.modalContent.$destroy();
    this.resolvePromise();
  }
}
