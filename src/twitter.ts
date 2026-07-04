import type { App } from "obsidian";
import { log } from "./log";
import { hasCompleteCredentials, type TwitterCredentials } from "./secrets";
import {
	XApiClient,
	type HttpRequest,
	type PostedTweet,
	type TweetPayload,
} from "./xApi";

const IMAGE_REGEX =
	/!?\[\[([\w .\-/]*\.(gif|jpe?g|tiff?|png|webp|bmp))]]/i;

const MIME_BY_EXTENSION: Record<string, string> = {
	gif: "image/gif",
	jpg: "image/jpeg",
	jpeg: "image/jpeg",
	tif: "image/tiff",
	tiff: "image/tiff",
	png: "image/png",
	webp: "image/webp",
	bmp: "image/bmp",
};

/** Thin wrapper around the X API client that owns the connection state. */
export class TwitterClient {
	private client: XApiClient | null = null;
	public isConnected = false;
	public lastError: string | null = null;

	constructor(
		private readonly app: App,
		private readonly request?: HttpRequest,
	) {}

	/**
	 * Connect and verify the credentials with a `me()` call. Any failure
	 * (bad credentials, an app not attached to a v2 Project, network) leaves the
	 * client disconnected and records the X-provided reason in {@link lastError}
	 * so the UI can show something actionable. NoteTweet uses the v2 API for
	 * posting too, so a forbidden v2 check means posting would fail as well.
	 */
	async connect(credentials: TwitterCredentials): Promise<boolean> {
		if (!hasCompleteCredentials(credentials)) {
			this.client = null;
			this.isConnected = false;
			this.lastError = null;
			return false;
		}

		try {
			this.client = new XApiClient(
				{
					consumerKey: credentials.apiKey,
					consumerSecret: credentials.apiSecret,
					accessToken: credentials.accessToken,
					accessTokenSecret: credentials.accessTokenSecret,
				},
				this.request,
			);
			await this.client.me();
			this.isConnected = true;
			this.lastError = null;
			return true;
		} catch (error) {
			this.client = null;
			this.isConnected = false;
			this.lastError =
				error instanceof Error ? error.message : String(error);
			return false;
		}
	}

	async postThread(content: string[]): Promise<PostedTweet[]> {
		const client = this.requireClient();
		const payloads: TweetPayload[] = [];
		for (const text of content) {
			payloads.push(await this.buildTweet(text));
		}

		// Mirrors twitter-api-v2's tweetThread: post sequentially, chaining
		// each tweet as a reply to the previously posted one.
		const posted: PostedTweet[] = [];
		for (const payload of payloads) {
			const previous = posted[posted.length - 1];
			if (previous) {
				payload.reply = { in_reply_to_tweet_id: previous.data.id };
			}
			posted.push(await client.createTweet(payload));
		}
		return posted;
	}

	async postTweet(text: string): Promise<PostedTweet> {
		const client = this.requireClient();
		return client.createTweet(await this.buildTweet(text));
	}

	async deleteTweets(tweets: { id: string }[]): Promise<boolean> {
		const client = this.requireClient();
		try {
			for (const tweet of tweets) {
				await client.deleteTweet(tweet.id);
			}
			return true;
		} catch (error) {
			log.error(`Could not delete tweets: ${error}`);
			return false;
		}
	}

	private requireClient(): XApiClient {
		if (!this.client) throw new Error("Not connected to Twitter.");
		return this.client;
	}

	/** Resolve embedded image links to uploaded media and strip them from text. */
	private async buildTweet(text: string): Promise<TweetPayload> {
		const client = this.requireClient();
		const mediaIds: string[] = [];
		let body = text;

		let match: RegExpExecArray | null;
		while ((match = IMAGE_REGEX.exec(body)) !== null) {
			const fileName = match[1];
			body = body.replace(IMAGE_REGEX, "").trim();

			const file = this.app.metadataCache.getFirstLinkpathDest(fileName, "");
			if (!file) {
				log.warning(`Could not find image '${fileName}' in the vault.`);
				continue;
			}

			const extension = fileName.split(".").pop()?.toLowerCase() ?? "";
			const mimeType = MIME_BY_EXTENSION[extension];
			const data = await this.app.vault.readBinary(file);
			try {
				mediaIds.push(await client.uploadMedia(data, mimeType));
			} catch {
				log.warning(`Could not upload image '${fileName}' to Twitter.`);
			}
		}

		if (mediaIds.length === 0) return { text: body };
		return { text: body, media: { media_ids: mediaIds } };
	}
}
