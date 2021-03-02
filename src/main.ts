import {App, MarkdownView, Plugin} from 'obsidian';
import {StatusesUpdate, TwitterClient} from "twitter-api-client";
import {NoteTweetSettings} from "./noteTweetSettings";
import {NoteTweetSettingsTab} from "./noteTweetSettingsTab";
import {TweetsPostedModal} from "./tweetsPostedModal";
import {TweetErrorModal} from "./tweetErrorModal";
import {SecureModeGetPasswordModal} from "./SecureModeGetPasswordModal";

const DEFAULT_SETTINGS: NoteTweetSettings = {
	apiKey: '',
	apiSecret: '',
	accessToken: '',
	accessTokenSecret: '',
	postTweetTag: '',
	secureMode: false,
}

const WELCOME_MESSAGE: string = "Loading NoteTweet🐦. Thanks for installing.";
const UNLOAD_MESSAGE: string = "Unloaded NoteTweet.";

export default class NoteTweet extends Plugin {
	settings: NoteTweetSettings;

	private twitterClient: TwitterClient;
	public isReady = false;

	async onload() {
		console.log(WELCOME_MESSAGE);

		await this.loadSettings();
		if (!this.settings.secureMode) {
			let {apiKey, apiSecret, accessToken, accessTokenSecret} = this.settings;
			this.connectToTwitter(apiKey, apiSecret, accessToken, accessTokenSecret);
		}

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
				let content = this.getCurrentDocumentContent(this.app);
				let threadContent = this.parseThreadFromText(content);

				await this.postThread(threadContent);
			}
		})

		this.addSettingTab(new NoteTweetSettingsTab(this.app, this));
	}

	private async postSelectedTweet() {
		let activeLeaf = this.app.workspace.activeLeaf;
		if (!activeLeaf || !(activeLeaf.view instanceof MarkdownView)) return;

		let editor = activeLeaf.view.sourceMode.cmEditor;

		if (editor.somethingSelected()) {
			let selection: string = editor.getSelection();

			await this.postTweet(selection);
		} else {
			new TweetErrorModal(this.app, "nothing selected.").open();
		}
	}

	private secureModeCheck() {
		if (this.settings.secureMode && !this.isReady) {
			new SecureModeGetPasswordModal(this.app, this).open();

			return this.isReady;
		}
		return this.isReady;
	}

	public connectToTwitter(apiKey: string, apiSecret: string, accessToken: string, accessTokenSecret: string) {
		try {
			this.twitterClient = new TwitterClient({
				apiKey, apiSecret, accessToken, accessTokenSecret
			});
			this.isReady = true;
		}
		catch (e) {
			console.log(e);
			this.isReady = false;
		}
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
	parseThreadFromText(text: string) {
		let contentArray = text.split("\n");
		let threadStartIndex = contentArray.indexOf("THREAD START") + 1;
		let threadEndIndex = contentArray.indexOf("THREAD END");
		return contentArray.slice(threadStartIndex, threadEndIndex).join("\n").split("\n---\n");
	}

	private async postThread(threadContent: string[]) {
		try {
			let postedTweets: StatusesUpdate[] = [];
			let previousPost: StatusesUpdate;
			for (const tweet of threadContent) {
				let isFirstTweet = threadContent.indexOf(tweet) == 0;

				previousPost = await this.twitterClient.tweets.statusesUpdate({
					status: tweet.trim(),
					...(!isFirstTweet && { in_reply_to_status_id: previousPost.id_str })
				})

				postedTweets.push(previousPost);
				await this.appendPostTweetTag(tweet);
			}

			new TweetsPostedModal(this.app, postedTweets).open();
		}
		catch (e) {
			new TweetErrorModal(this.app, e.data || e).open();
		}
	}

	private async postTweet(tweet: string) {
		try {
			let newStatus = await this.twitterClient.tweets.statusesUpdate({
				status: tweet.trim(),
			});

			new TweetsPostedModal(this.app, [newStatus]).open();

			if (this.settings.postTweetTag)
				await this.appendPostTweetTag(tweet);

			return newStatus;
		}
		catch (e) {
			new TweetErrorModal(this.app, e.data || e).open();
		}
	}

	private async appendPostTweetTag(selection: string) {
		let active_view = this.app.workspace.getActiveViewOfType(MarkdownView);
		if (active_view == null) return;

		let editor = active_view.sourceMode.cmEditor;
		let doc = editor.getDoc();

		let pageContent = doc.getValue();

		pageContent = pageContent.replace(selection.trim(), `${selection.trim()} ${this.settings.postTweetTag}`);
		doc.setValue(pageContent);

		editor.focus();
	}
}

