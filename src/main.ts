import {debounce, Editor, MarkdownView, Notice, Plugin, TFile} from "obsidian";
import {TwitterHandler} from "./TwitterHandler";
import {DEFAULT_SETTINGS, NoteTweetSettings, NoteTweetSettingsTab,} from "./settings";
import {TweetsPostedModal} from "./Modals/TweetsPostedModal/TweetsPostedModal";
import {TweetErrorModal} from "./Modals/TweetErrorModal";
import {SecureModeGetPasswordModal} from "./Modals/SecureModeGetPasswordModal/SecureModeGetPasswordModal";
import {PostTweetModal} from "./Modals/PostTweetModal";
import {log} from "./ErrorModule/logManager";
import {ConsoleErrorLogger} from "./ErrorModule/consoleErrorLogger";
import {GuiLogger} from "./ErrorModule/guiLogger";
import {NoteTweetScheduler} from "./scheduling/NoteTweetScheduler";
import {SelfHostedScheduler} from "./scheduling/SelfHostedScheduler";

const WELCOME_MESSAGE: string = "Loading NoteTweet🐦. Thanks for installing.";
const UNLOAD_MESSAGE: string = "Unloaded NoteTweet.";

export default class NoteTweet extends Plugin {
  settings: NoteTweetSettings;
  scheduler: NoteTweetScheduler;

  public twitterHandler: TwitterHandler;

  async onload() {
    console.log(WELCOME_MESSAGE);

    await this.loadSettings();
    this.twitterHandler = new TwitterHandler(this);
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

    /*START.DEVCMD*/
    this.addCommand({
      id: 'reloadNoteTweet',
      name: 'Reload NoteTweet (dev)',
      callback: () => { // @ts-ignore - for this.app.plugins
        const id: string = this.manifest.id, plugins = this.app.plugins;
        plugins.disablePlugin(id).then(() => plugins.enablePlugin(id));
      },
    });
    /*END.DEVCMD*/

    log.register(new ConsoleErrorLogger())
        .register(new GuiLogger(this));

    this.addSettingTab(new NoteTweetSettingsTab(this.app, this));

    if (this.settings.scheduling.enabled) {
      this.scheduler = new SelfHostedScheduler(this.settings.scheduling.url, this.settings.scheduling.password);
    }
  }

  private postTweetMode() {
    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    let editor: Editor;

    if (view instanceof MarkdownView) {
      editor = view.editor;
    }

    if (editor?.somethingSelected()) {
      let selection = editor.getSelection();

      try {
        selection = this.parseThreadFromText(selection).join("--nt_sep--");
        new PostTweetModal(this.app, this.twitterHandler, this.scheduler, {
          text: selection,
          thread: true,
        }).open();
      } catch {
        new PostTweetModal(this.app, this.twitterHandler, this.scheduler, {
          text: selection,
          thread: false,
        }).open();
      } // Intentionally suppressing exceptions. They're expected.
    } else {
      new PostTweetModal(this.app, this.twitterHandler, this.scheduler).open();
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
    const file = this.app.workspace.getActiveFile();
    let content = await this.getFileContent(file);
    let threadContent: string[];
    try {
      threadContent = this.parseThreadFromText(content);
    } catch (e) {
      log.logError(`error in parsing thread in file ${file?.name}. ${e}`);
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
      log.logError(`failed attempted to post tweets. ${e}`);
    }
  }

  private async postSelectedTweet() {
    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    let editor;

    if (view instanceof MarkdownView) {
      editor = view.editor;
    } else {
      return;
    }

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
          await this.appendPostTweetTag(tweet.text);
        }
      } catch (e) {
        log.logError(`failed attempt to post selected. ${e}`);
      }
    } else {
      log.logWarning(`tried to post selected but nothing was selected.`)
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
        else log.logWarning("could not connect to Twitter");
      })
      .catch(() => {
        modal.close();
        log.logWarning("could not connect to Twitter.");
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

    if (this.settings.scheduling.enabled) {
        await this.updateSchedulerSettings();
    }
  }

  private updateSchedulerSettings: () => void = debounce(async () => {
    await this.scheduler.updateSchedule(this.settings.scheduling.cronStrings);
  }, 10000, true);

  async getFileContent(file: TFile): Promise<string> {
    if (file.extension != "md") return null;

    return await this.app.vault.read(file);
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

  private async appendPostTweetTag(selection: string) {
    const currentFile = this.app.workspace.getActiveFile();
    let pageContent = await this.getFileContent(currentFile);

    pageContent = pageContent.replace(
      selection.trim(),
      `${selection.trim()} ${this.settings.postTweetTag}`
    );

    await this.app.vault.modify(currentFile, pageContent);
  }
}
