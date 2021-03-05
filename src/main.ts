import {App, MarkdownView, Plugin} from 'obsidian';
import {TwitterHandler} from "./TwitterHandler";
import {DEFAULT_SETTINGS, NoteTweetSettings, NoteTweetSettingsTab} from "./settings";
import {TweetsPostedModal} from "./Modals/tweetsPostedModal";
import {TweetErrorModal} from "./Modals/tweetErrorModal";
import {SecureModeGetPasswordModal} from "./Modals/SecureModeGetPasswordModal";

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
			id: 'post-selected-as-tweet',
			name: 'Post Selected as Tweet',
			callback: async () => {
				if (this.secureModeCheck()) {
					await this.postSelectedTweet();
				}
			}
		});

		this.addCommand({
			id: 'post-file-as-thread',
			name: 'Post File as Thread',
			callback: async () => {
				if (this.secureModeCheck()) {
					await this.postThreadInFile();
				}
			}
		})

		this.addSettingTab(new NoteTweetSettingsTab(this.app, this));
	}

	private async postThreadInFile() {
		let content = this.getCurrentDocumentContent(this.app);
		let threadContent = this.parseThreadFromText(content);

		try {
			let postedTweets = await this.twitterHandler.postThread(threadContent);
			new TweetsPostedModal(this.app, postedTweets).open();

			if (this.settings.postTweetTag)
				postedTweets.forEach(tweet => this.appendPostTweetTag(tweet.text));
		} catch (e) {
			new TweetErrorModal(this.app, e.data || e).open();
		}
	}

	public connectToTwitterWithPlainSettings() {
		if (!this.settings.secureMode) {
			let {apiKey, apiSecret, accessToken, accessTokenSecret} = this.settings;
			if (!apiKey || !apiSecret || !accessToken || !accessTokenSecret) return;

			this.twitterHandler.connectToTwitter(apiKey, apiSecret, accessToken, accessTokenSecret);
		}
	}

	private async postSelectedTweet() {
		let view = this.app.workspace.getActiveViewOfType(MarkdownView);
		let editor = view.sourceMode.cmEditor;

		if (editor.somethingSelected()) {
			let selection: string = editor.getSelection();

			try {
				let tweet = await this.twitterHandler.postTweet(selection);

				if (this.settings.postTweetTag)
					await this.appendPostTweetTag(tweet.text);

				new TweetsPostedModal(this.app, [tweet]).open();
			}
			catch (e) {
				new TweetErrorModal(this.app, e.data || e).open();
			}

		} else {
			new TweetErrorModal(this.app, "nothing selected.").open();
		}
	}

	private secureModeCheck() {
		if (this.settings.secureMode && !this.twitterHandler.isConnectedToTwitter) {
			new SecureModeGetPasswordModal(this.app, this).open();

			return this.twitterHandler.isConnectedToTwitter;
		}
		return this.twitterHandler.isConnectedToTwitter;
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
		return contentArray.slice(threadStartIndex, threadEndIndex).join("\n").split("\n---\n");
	}

	private appendPostTweetTag(selection: string) {
		let editor = this.app.workspace.getActiveViewOfType(MarkdownView).sourceMode.cmEditor;
		let doc = editor.getDoc();
		let pageContent = this.getCurrentDocumentContent(this.app);

		pageContent = pageContent.replace(selection.trim(), `${selection.trim()} ${this.settings.postTweetTag}`);
		doc.setValue(pageContent);

		editor.focus();
	}
}

