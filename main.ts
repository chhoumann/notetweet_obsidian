import {App, MarkdownView, Plugin} from 'obsidian';
import {TwitterClient} from "twitter-api-client";
import {NoteTweetSettings} from "./noteTweetSettings";
import {NoteTweetSettingsTab} from "./noteTweetSettingsTab";
import {TweetPostedModal} from "./tweetPostedModal";
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

		this.addCommand({
			id: 'post-file-as-thread',
			name: 'Post File as Thread',
			callback: async () => {
				// Differentiate tweets
				let active_view = this.app.workspace.getActiveViewOfType(MarkdownView);
				let editor = active_view.sourceMode.cmEditor;
				let doc = editor.getDoc();
				let contentArray = doc.getValue().split("\n");

				let startIndex = contentArray.indexOf("THREAD START") + 1;
				let endIndex = contentArray.indexOf("THREAD END");

				let threadContent = contentArray.slice(startIndex, endIndex).join("\n").split("\n---\n");

				// post thread
				let post = await this.postTweet(threadContent[0].trim());

				for (let i = 1; i < threadContent.length; i++) {
					post = await this.twitterClient.tweets.statusesUpdate({
						status: threadContent[i].trim(),
						in_reply_to_status_id: post.id_str
					});
				}
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

	private async postTweet(tweet: string) {
		try {
			let newStatus = await this.twitterClient.tweets.statusesUpdate({
				status: tweet
			});

			new TweetPostedModal(this.app, newStatus).open();

			//if (this.settings.postTweetTag)
			//	await this.appendPostTweetTag(tweet);

			return newStatus;
		}
		catch (e) {
			new TweetErrorModal(this.app, e.data).open();
		}
	}

	private async appendPostTweetTag(selection: string) {
		let active_view = this.app.workspace.getActiveViewOfType(MarkdownView);
		if (active_view == null) return;

		let editor = active_view.sourceMode.cmEditor;
		let doc = editor.getDoc();

		doc.replaceSelection(`${selection} ${this.settings.postTweetTag}`);

		editor.focus();
	}
}

