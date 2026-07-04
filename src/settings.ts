export interface NoteTweetSettings {
	/** Tag appended to a note's text after its tweet is posted (empty = off). */
	postTweetTag: string;
	/** Split pasted/typed content into multiple tweets at the 280-char limit. */
	autoSplitTweets: boolean;
	scheduling: {
		enabled: boolean;
		url: string;
	};
}

export const DEFAULT_SETTINGS: NoteTweetSettings = {
	postTweetTag: "",
	autoSplitTweets: true,
	scheduling: {
		enabled: false,
		url: "",
	},
};
