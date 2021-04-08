import { App, MarkdownView, Plugin, Notice } from "obsidian";
import { TwitterHandler } from "./TwitterHandler";
import {
  DEFAULT_SETTINGS,
  NoteTweetSettings,
  NoteTweetSettingsTab,
} from "./Settings";
import { TweetsPostedModal } from "./Modals/TweetsPostedModal/TweetsPostedModal";
import { TweetErrorModal } from "./Modals/TweetErrorModal/TweetErrorModal";
import { SecureModeGetPasswordModal } from "./Modals/SecureModeGetPasswordModal/SecureModeGetPasswordModal";
import { StatusesUpdate } from "twitter-api-client";
import { PostTweetModal } from "./Modals/PostTweetModal/PostTweetModal";

const WELCOME_MESSAGE: string = "Loading NoteTweet🐦. Thanks for installing.";
const UNLOAD_MESSAGE: string = "Unloaded NoteTweet.";

export default class NoteTweet extends Plugin {
  settings: NoteTweetSettings;

  public twitterHandler: TwitterHandler;

  async onload() {
    console.log(WELCOME_MESSAGE);

    await this.loadSettings();
    this.twitterHandler = new TwitterHandler();
    this.connectToTwitterWithPlainSettings();

    this.addCommand({
      id: "post-selected-as-tweet",
      name: "Post Selected as Tweet",
      callback: async () => {
        if (this.twitterHandler.isConnectedToTwitter)
          await this.postSelectedTweet();
        else if (this.settings.secureMode)
          await this.secureModeProxy(
            async () => await this.postSelectedTweet()
          );
        else {
          this.connectToTwitterWithPlainSettings();

          if (!this.twitterHandler.isConnectedToTwitter)
            new TweetErrorModal(this.app, "Not connected to Twitter").open();
          else await this.postSelectedTweet();
        }
      },
    });

    this.addCommand({
      id: "post-file-as-thread",
      name: "Post File as Thread",
      callback: async () => {
        if (this.twitterHandler.isConnectedToTwitter)
          await this.postThreadInFile();
        else if (this.settings.secureMode)
          await this.secureModeProxy(async () => await this.postThreadInFile());
        else {
          this.connectToTwitterWithPlainSettings();

          if (!this.twitterHandler.isConnectedToTwitter)
            new TweetErrorModal(this.app, "Not connected to Twitter").open();
          else await this.postThreadInFile();
        }
      },
    });

    this.addCommand({
      id: "post-tweet",
      name: "Post Tweet",
      callback: async () => {
        if (this.twitterHandler.isConnectedToTwitter) this.postTweetMode();
        else if (this.settings.secureMode)
          await this.secureModeProxy(() => this.postTweetMode());
        else {
          this.connectToTwitterWithPlainSettings();

          if (!this.twitterHandler.isConnectedToTwitter)
            new TweetErrorModal(this.app, "Not connected to Twitter").open();
          else this.postTweetMode();
        }
      },
    });

    this.addSettingTab(new NoteTweetSettingsTab(this.app, this));
  }

  private postTweetMode() {
    let view = this.app.workspace.getActiveViewOfType(MarkdownView);
    let editor = view.sourceMode.cmEditor;

    if (editor.somethingSelected()) {
      let selection = editor.getSelection();

      try {
        selection = this.parseThreadFromText(selection).join("--nt_sep--");
        new PostTweetModal(this.app, this.twitterHandler, {
          text: selection,
          thread: true,
        }).open();
      } catch {
        new PostTweetModal(this.app, this.twitterHandler, {
          text: selection,
          thread: false,
        }).open();
      } // Intentionally suppressing exceptions. They're expected.
    } else {
      new PostTweetModal(this.app, this.twitterHandler).open();
    }
  }

  public connectToTwitterWithPlainSettings() {
    if (!this.settings.secureMode) {
      let { apiKey, apiSecret, accessToken, accessTokenSecret } = this.settings;
      if (!apiKey || !apiSecret || !accessToken || !accessTokenSecret) return;

      this.twitterHandler.connectToTwitter(
        apiKey,
        apiSecret,
        accessToken,
        accessTokenSecret
      );
    }
  }

  private async postThreadInFile() {
    let content = this.getCurrentDocumentContent(this.app);
    let threadContent: string[];
    try {
      threadContent = this.parseThreadFromText(content);
    } catch (e) {
      new TweetErrorModal(this.app, e).open();
      return;
    }

    try {
      let postedTweets = await this.twitterHandler.postThread(threadContent);
      let postedModal = new TweetsPostedModal(
        this.app,
        postedTweets,
        this.twitterHandler
      );

      await postedModal.waitForClose;
      if (!postedModal.userDeletedTweets && this.settings.postTweetTag) {
        postedTweets.forEach((tweet) => this.appendPostTweetTag(tweet.text));
      }
    } catch (e) {
      new TweetErrorModal(this.app, e.data || e).open();
    }
  }

  private async postSelectedTweet() {
    let view = this.app.workspace.getActiveViewOfType(MarkdownView);
    let editor = view.sourceMode.cmEditor;

    if (editor.somethingSelected()) {
      let selection: string = editor.getSelection();

      try {
        let tweet = await this.twitterHandler.postTweet(selection);
        let postedModal = new TweetsPostedModal(
          this.app,
          [tweet],
          this.twitterHandler
        );

        await postedModal.waitForClose;
        if (!postedModal.userDeletedTweets && this.settings.postTweetTag) {
          this.appendPostTweetTag(tweet.text);
        }
      } catch (e) {
        new TweetErrorModal(this.app, e.data || e).open();
      }
    } else {
      new TweetErrorModal(this.app, "nothing selected.").open();
    }
  }

  private async secureModeProxy(callback: any) {
    if (
      !(this.settings.secureMode && !this.twitterHandler.isConnectedToTwitter)
    )
      return;

    let modal = new SecureModeGetPasswordModal(this.app, this);

    modal.waitForClose
      .then(async () => {
        if (this.twitterHandler.isConnectedToTwitter) await callback();
        else new Notice("Could not connect to Twitter");
      })
      .catch(() => {
        modal.close();
        new Notice("Could not connect to Twitter.");
      });
  }

  onunload() {
    console.log(UNLOAD_MESSAGE);
  }

  async loadSettings() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }

  getCurrentDocumentContent(app: App) {
    let active_view = app.workspace.getActiveViewOfType(MarkdownView);
    let editor = active_view.sourceMode.cmEditor;
    let doc = editor.getDoc();

    return doc.getValue();
  }

  // All threads start with THREAD START and ends with THREAD END. To separate tweets in a thread,
  // one should use use a newline and '---' (this prevents markdown from believing the above tweet is a heading).
  // We also purposefully remove the newline after the separator - otherwise tweets will be posted with a newline
  // as their first line.
  private parseThreadFromText(text: string) {
    let contentArray = text.split("\n");
    let threadStartIndex = contentArray.indexOf("THREAD START") + 1;
    let threadEndIndex = contentArray.indexOf("THREAD END");

    if (threadStartIndex == 0 || threadEndIndex == -1) {
      throw new Error("Failed to detect THREAD START or THREAD END");
    }

    let content = contentArray
      .slice(threadStartIndex, threadEndIndex)
      .join("\n")
      .split("\n---\n");
    if (content.length == 1 && content[0] == "") {
      throw new Error("Please write something in your thread.");
    }

    return content.map((txt) => txt.trim());
  }

  private appendPostTweetTag(selection: string) {
    let editor = this.app.workspace.getActiveViewOfType(MarkdownView).sourceMode
      .cmEditor;
    let doc = editor.getDoc();
    let pageContent = this.getCurrentDocumentContent(this.app);

    pageContent = pageContent.replace(
      selection.trim(),
      `${selection.trim()} ${this.settings.postTweetTag}`
    );

    let scrollInfo = editor.getScrollerElement();
    doc.setValue(pageContent);
    editor.scrollTo(scrollInfo.offsetWidth, scrollInfo.offsetHeight);

    editor.focus();
  }
}
