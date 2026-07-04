import type { App } from "obsidian";
import { TwitterApi } from "twitter-api-v2";
import type { SendTweetV2Params, TweetV2PostTweetResult } from "twitter-api-v2";
import { log } from "./log";
import { hasCompleteCredentials, type TwitterCredentials } from "./secrets";

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

function humanError(error: unknown): string {
	if (typeof error === "object" && error !== null && "data" in error) {
		const data = error.data;
		if (typeof data === "object" && data !== null) {
			if ("detail" in data && typeof data.detail === "string") return data.detail;
			if ("title" in data && typeof data.title === "string") return data.title;
		}
	}
	if (typeof error === "object" && error !== null && "message" in error) {
		return String(error.message);
	}
	return String(error);
}

function describeError(error: unknown): string {
	if (typeof error !== "object" || error === null) return String(error);
	const parts: string[] = [];
	if ("code" in error) parts.push(`code=${String(error.code)}`);
	if ("data" in error) {
		try {
			parts.push(`data=${JSON.stringify(error.data)}`);
		} catch {
			// non-serializable error payload; skip it
		}
	}
	if ("message" in error && parts.length === 0) parts.push(String(error.message));
	return parts.length > 0 ? parts.join(" ") : String(error);
}

/** Thin wrapper around twitter-api-v2 that owns the connection state. */
export class TwitterClient {
	private client: TwitterApi | null = null;
	public isConnected = false;
	public lastError: string | null = null;

	constructor(private readonly app: App) {}

	/**
	 * Connect and verify the credentials with a `v2.me()` call. Any failure
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
			this.client = new TwitterApi({
				appKey: credentials.apiKey,
				appSecret: credentials.apiSecret,
				accessToken: credentials.accessToken,
				accessSecret: credentials.accessTokenSecret,
			});
			await this.client.v2.me();
			this.isConnected = true;
			this.lastError = null;
			return true;
		} catch (error) {
			this.client = null;
			this.isConnected = false;
			this.lastError = humanError(error);
			log.message(`Twitter authentication failed: ${describeError(error)}`);
			return false;
		}
	}

	async postThread(content: string[]): Promise<TweetV2PostTweetResult[]> {
		const client = this.requireClient();
		const tweets: SendTweetV2Params[] = [];
		for (const text of content) {
			tweets.push(await this.buildTweet(text));
		}
		return client.v2.tweetThread(tweets);
	}

	async postTweet(text: string): Promise<TweetV2PostTweetResult> {
		const client = this.requireClient();
		return client.v2.tweet(await this.buildTweet(text));
	}

	async deleteTweets(tweets: { id: string }[]): Promise<boolean> {
		const client = this.requireClient();
		try {
			for (const tweet of tweets) {
				await client.v2.deleteTweet(tweet.id);
			}
			return true;
		} catch (error) {
			log.error(`Could not delete tweets: ${error}`);
			return false;
		}
	}

	private requireClient(): TwitterApi {
		if (!this.client) throw new Error("Not connected to Twitter.");
		return this.client;
	}

	/** Resolve embedded image links to uploaded media and strip them from text. */
	private async buildTweet(text: string): Promise<SendTweetV2Params> {
		const client = this.requireClient();
		const mediaIds: string[] = [];
		let body = text;

		let match: RegExpExecArray | null;
		while ((match = IMAGE_REGEX.exec(body)) !== null) {
			const fileName = match[1];
			body = body.replace(IMAGE_REGEX, "").trim();

			if (typeof Buffer === "undefined") {
				log.warning(
					`Image attachments (${fileName}) are only supported on desktop.`,
				);
				continue;
			}

			const file = this.app.metadataCache.getFirstLinkpathDest(fileName, "");
			if (!file) {
				log.warning(`Could not find image '${fileName}' in the vault.`);
				continue;
			}

			const extension = fileName.split(".").pop()?.toLowerCase() ?? "";
			const mimeType = MIME_BY_EXTENSION[extension];
			const data = Buffer.from(await this.app.vault.readBinary(file));
			const mediaId = await client.v1.uploadMedia(data, { mimeType });

			if (mediaId) mediaIds.push(mediaId);
			else log.warning(`Could not upload image '${fileName}' to Twitter.`);
		}

		if (mediaIds.length === 0) return { text: body };

		// twitter-api-v2 types media_ids as a 1-4 element tuple; the ids we collect
		// are validated at runtime and capped by Twitter's own limit.
		const media = { media_ids: mediaIds } as NonNullable<
			SendTweetV2Params["media"]
		>;
		return { text: body, media };
	}
}
