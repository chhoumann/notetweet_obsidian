import { Notice, requestUrl } from "obsidian";
import type { ScheduledTweet } from "./tweet";
import { formatDateTime } from "./datetime";

export interface Scheduler {
	scheduleTweet(tweet: ScheduledTweet): Promise<void>;
	getScheduledTweets(): Promise<ScheduledTweet[]>;
	deleteScheduledTweet(tweet: ScheduledTweet): Promise<void>;
	updateTweet(tweet: ScheduledTweet): Promise<void>;
}

/**
 * Talks to a user-hosted scheduler endpoint over HTTP. Uses Obsidian's
 * `requestUrl` (CORS-free, works on mobile) with HTTP Basic auth carrying the
 * scheduler password - matching the auth the previous `got`-based client sent.
 */
export class SelfHostedScheduler implements Scheduler {
	constructor(
		private readonly url: string,
		private readonly password: string,
	) {}

	async scheduleTweet(tweet: ScheduledTweet): Promise<void> {
		await this.send("/scheduleTweet", "POST", {
			tweet,
			postAt: tweet.postat,
		});
		const when = formatDateTime(tweet.postat);
		new Notice(
			`Scheduled '${tweet.content[0].slice(0, 10)}...' for ${when}`,
		);
	}

	async getScheduledTweets(): Promise<ScheduledTweet[]> {
		const response = await this.send("/scheduledTweets", "GET");
		return response.json ?? [];
	}

	async deleteScheduledTweet(tweet: ScheduledTweet): Promise<void> {
		await this.send("/deleteScheduled", "DELETE", { tweet });
	}

	async updateTweet(tweet: ScheduledTweet): Promise<void> {
		await this.send("/updateTweet", "POST", {
			tweet,
			postAt: tweet.postat,
		});
	}

	private async send(path: string, method: string, body?: unknown) {
		const response = await requestUrl({
			url: `${this.url}${path}`,
			method,
			headers: { Authorization: `Basic ${btoa(`:${this.password}`)}` },
			throw: false,
			...(body !== undefined
				? { contentType: "application/json", body: JSON.stringify(body) }
				: {}),
		});
		if (response.status < 200 || response.status >= 300) {
			throw new Error(
				`Scheduler request to ${path} failed with status ${response.status}.`,
			);
		}
		return response;
	}
}
