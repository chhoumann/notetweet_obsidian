/**
 * Hand-rolled X API v2 client on top of Obsidian's `requestUrl`. Replaces
 * twitter-api-v2, whose Node-builtin transport made the plugin desktop-only
 * and tripped the community-directory scanner, and whose v1.1 media upload
 * stopped working when X sunset that endpoint in June 2025.
 */

import { arrayBufferToBase64, requestUrl } from "obsidian";
import { oauth1Header, percentEncode, type OAuth1Credentials } from "./oauth1";

export interface PostedTweet {
	data: { id: string; text: string };
}
export interface TweetPayload {
	text: string;
	media?: { media_ids: string[] };
	reply?: { in_reply_to_tweet_id: string };
}
export interface XUser {
	id: string;
	name: string;
	username: string;
}
export interface HttpResponse {
	status: number;
	text: string;
	json: unknown;
}
export type HttpRequest = (req: {
	url: string;
	method: string;
	headers: Record<string, string>;
	body?: string;
}) => Promise<HttpResponse>;

const BASE_URL = "https://api.x.com";

/**
 * X accepts multi-MiB APPEND segments, but base64 inflates each request body
 * by 4/3; 1 MiB raw chunks keep individual requests comfortably small.
 */
const GIF_CHUNK_BYTES = 1024 * 1024;

/**
 * GIF processing is usually instant; ~10 polls of `check_after_secs` each is
 * far beyond any healthy processing time, so give up rather than spin.
 */
const MAX_STATUS_POLLS = 10;

/** Default adapter: Obsidian's fetch that bypasses CORS on desktop and mobile. */
const obsidianRequest: HttpRequest = async (req) => {
	const response = await requestUrl({
		url: req.url,
		method: req.method,
		headers: req.headers,
		body: req.body,
		throw: false,
	});
	// `.json` is a getter that throws on non-JSON bodies (e.g. HTML error
	// pages); error extraction still works off the status code alone.
	let json: unknown;
	try {
		json = response.json;
	} catch {
		json = undefined;
	}
	return { status: response.status, text: response.text, json };
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

/**
 * Human-readable reason for a failed API call, in the priority X actually
 * populates: v2 per-item errors first, then RFC 7807 problem fields.
 */
export function extractApiError(status: number, body: unknown): string {
	if (isRecord(body)) {
		const errors = body.errors;
		if (Array.isArray(errors) && errors.length > 0) {
			const first: unknown = errors[0];
			if (isRecord(first)) {
				if (typeof first.message === "string") return first.message;
				if (typeof first.detail === "string") return first.detail;
			}
		}
		if (typeof body.title === "string") return body.title;
		if (typeof body.detail === "string") return body.detail;
	}
	return `HTTP ${status}`;
}

/** The media id from `{ data: { id } }` upload responses; throws when absent. */
function mediaIdOf(json: unknown): string {
	const data = isRecord(json) ? json.data : undefined;
	if (isRecord(data) && typeof data.id === "string") return data.id;
	throw new Error("X media upload returned no media id.");
}

interface ProcessingInfo {
	state: string;
	checkAfterSecs: number | undefined;
}

function processingInfoOf(json: unknown): ProcessingInfo | undefined {
	const data = isRecord(json) ? json.data : undefined;
	const info = isRecord(data) ? data.processing_info : undefined;
	if (!isRecord(info) || typeof info.state !== "string") return undefined;
	return {
		state: info.state,
		checkAfterSecs:
			typeof info.check_after_secs === "number"
				? info.check_after_secs
				: undefined,
	};
}

function sleep(ms: number): Promise<void> {
	const { promise, resolve } = Promise.withResolvers<void>();
	window.setTimeout(resolve, ms);
	return promise;
}

export class XApiClient {
	constructor(
		private readonly credentials: OAuth1Credentials,
		private readonly request: HttpRequest = obsidianRequest,
	) {}

	async me(): Promise<XUser> {
		const json = await this.call("GET", "/2/users/me");
		const data = isRecord(json) ? json.data : undefined;
		if (
			isRecord(data) &&
			typeof data.id === "string" &&
			typeof data.name === "string" &&
			typeof data.username === "string"
		) {
			return { id: data.id, name: data.name, username: data.username };
		}
		throw new Error("Unexpected response from /2/users/me.");
	}

	async createTweet(payload: TweetPayload): Promise<PostedTweet> {
		const json = await this.call("POST", "/2/tweets", { body: payload });
		const data = isRecord(json) ? json.data : undefined;
		if (
			isRecord(data) &&
			typeof data.id === "string" &&
			typeof data.text === "string"
		) {
			return { data: { id: data.id, text: data.text } };
		}
		throw new Error("Unexpected response from /2/tweets.");
	}

	async deleteTweet(id: string): Promise<void> {
		await this.call("DELETE", `/2/tweets/${id}`);
	}

	/** Uploads one image/GIF; resolves to the media id string for media_ids. */
	async uploadMedia(data: ArrayBuffer, mimeType: string): Promise<string> {
		if (mimeType === "image/gif") return this.uploadGif(data);
		const json = await this.call("POST", "/2/media/upload", {
			body: {
				media: arrayBufferToBase64(data),
				media_category: "tweet_image",
				media_type: mimeType,
			},
		});
		return mediaIdOf(json);
	}

	/**
	 * One-shot /2/media/upload rejects GIFs (its media_type enum lacks
	 * image/gif), so GIFs go through the chunked initialize/append/finalize
	 * flow with the tweet_gif category.
	 */
	private async uploadGif(data: ArrayBuffer): Promise<string> {
		const initialized = await this.call("POST", "/2/media/upload/initialize", {
			body: {
				media_type: "image/gif",
				total_bytes: data.byteLength,
				media_category: "tweet_gif",
			},
		});
		const id = mediaIdOf(initialized);

		for (let offset = 0; offset < data.byteLength; offset += GIF_CHUNK_BYTES) {
			await this.call("POST", `/2/media/upload/${id}/append`, {
				body: {
					media: arrayBufferToBase64(
						data.slice(offset, offset + GIF_CHUNK_BYTES),
					),
					segment_index: offset / GIF_CHUNK_BYTES,
				},
			});
		}

		const finalized = await this.call("POST", `/2/media/upload/${id}/finalize`);
		return this.awaitProcessing(id, finalized);
	}

	/**
	 * Waits for async media processing after FINALIZE by polling
	 * GET /2/media/upload?command=STATUS. A response without processing_info
	 * means the media is already usable.
	 */
	private async awaitProcessing(id: string, finalized: unknown): Promise<string> {
		let info = processingInfoOf(finalized);
		for (let attempt = 0; attempt < MAX_STATUS_POLLS; attempt++) {
			if (!info || info.state === "succeeded") return id;
			if (info.state === "failed") {
				throw new Error("X could not process the uploaded media.");
			}
			await sleep((info.checkAfterSecs ?? 1) * 1000);
			const status = await this.call("GET", "/2/media/upload", {
				query: { command: "STATUS", media_id: id },
			});
			info = processingInfoOf(status);
		}
		throw new Error("Timed out waiting for X to process the uploaded media.");
	}

	/** Signs and sends one JSON request; throws a human message on >= 400. */
	private async call(
		method: string,
		path: string,
		options: { query?: Record<string, string>; body?: unknown } = {},
	): Promise<unknown> {
		const url = `${BASE_URL}${path}`;
		// Only query params participate in the OAuth signature; JSON bodies
		// are not signed under OAuth 1.0a.
		const authorization = await oauth1Header({
			method,
			url,
			credentials: this.credentials,
			params: options.query ?? {},
		});

		const headers: Record<string, string> = { Authorization: authorization };
		let body: string | undefined;
		if (options.body !== undefined) {
			headers["Content-Type"] = "application/json";
			body = JSON.stringify(options.body);
		}

		// Encode the query string with the same RFC 3986 encoder used for the
		// signature so the sent URL always matches what was signed.
		const query = Object.entries(options.query ?? {})
			.map(([key, value]) => `${percentEncode(key)}=${percentEncode(value)}`)
			.join("&");

		const response = await this.request({
			url: query ? `${url}?${query}` : url,
			method,
			headers,
			body,
		});
		if (response.status >= 400) {
			throw new Error(extractApiError(response.status, response.json));
		}
		return response.json;
	}
}
