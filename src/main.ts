import {App, MarkdownView, Plugin} from 'obsidian';
import {StatusesUpdate, TwitterClient} from "twitter-api-client";
import {NoteTweetSettings} from "./noteTweetSettings";
import {NoteTweetSettingsTab} from "./noteTweetSettingsTab";
import {TweetsPostedModal} from "./tweetsPostedModal";
import {TweetErrorModal} from "./tweetErrorModal";

const DEFAULT_SETTINGS: NoteTweetSettings = {
	APIKey: '',
	APISecret: '',
	accessToken: '',
	accessTokenSecret: '',
	postTweetTag: ''
}

const WELCOME_MESSAGE: string = "Loading NoteTweet🐦. Thanks for installing.";
const UNLOAD_MESSAGE: string = "Unloaded NoteTweet.";

export default class NoteTweet extends Plugin {
	settings: NoteTweetSettings;

	private twitterClient: TwitterClient;

	async onload() {
		console.log(WELCOME_MESSAGE);

		await this.loadSettings();
		// TODO: Add some error handling. What if no settings are provided?
		this.twitterClient = new TwitterClient({
			apiKey: this.settings.APIKey,
			apiSecret: this.settings.APISecret,
			accessToken: this.settings.accessToken,
			accessTokenSecret: this.settings.accessTokenSecret
		});

		this.addCommand({
			id: 'post-selected-as-tweet',
			name: 'Post Selected as Tweet',
			callback: async () => {
				// TODO: Block this if user hasn't provided settings
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
		});

		function getCurrentDocumentContent(app: App) {
			let active_view = app.workspace.getActiveViewOfType(MarkdownView);
			let editor = active_view.sourceMode.cmEditor;
			let doc = editor.getDoc();

			return doc.getValue();
		}

		// All threads start with THREAD START and ends with THREAD END. To separate tweets in a thread,
		// one should use use a newline and '---' (this prevents markdown from believing the above tweet is a heading).
		// We also purposefully remove the newline after the separator - otherwise tweets will be posted with a newline
		// as their first line.
		function parseThreadFromText(text: string) {
			let contentArray = text.split("\n");
			let threadStartIndex = contentArray.indexOf("THREAD START") + 1;
			let threadEndIndex = contentArray.indexOf("THREAD END");
			return contentArray.slice(threadStartIndex, threadEndIndex).join("\n").split("\n---\n");
		}

		this.addCommand({
			id: 'post-file-as-thread',
			name: 'Post File as Thread',
			callback: async () => {
				let content = getCurrentDocumentContent(this.app);
				let threadContent = parseThreadFromText(content);

				await this.postThread(threadContent);
			}
		})

		this.addSettingTab(new NoteTweetSettingsTab(this.app, this));
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
			}

			new TweetsPostedModal(this.app, postedTweets).open();
		}
		catch (e) {
			new TweetErrorModal(this.app, e.data).open();
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
			new TweetErrorModal(this.app, e.data).open();
		}
	}

	// TODO: Fix this
	private async appendPostTweetTag(selection: string) {
		let active_view = this.app.workspace.getActiveViewOfType(MarkdownView);
		if (active_view == null) return;

		let editor = active_view.sourceMode.cmEditor;
		let doc = editor.getDoc();

		let pageContent = doc.getValue();
		pageContent.replace(selection, `${selection} ${this.settings.postTweetTag}`);
		doc.setValue(pageContent);

		editor.focus();
	}
}

