import { XApiClient, extractApiError } from "./xApi";
import type { HttpRequest, HttpResponse, TweetPayload } from "./xApi";
import type { OAuth1Credentials } from "./oauth1";

// xApi.ts imports { requestUrl, arrayBufferToBase64 } from "obsidian", and
// the shared test stub (tests/obsidian-stub.ts) does not export
// arrayBufferToBase64. Provide a real polyfill so the base64 assertions
// below exercise a genuine byte-for-byte conversion; requestUrl is a vi.fn()
// because every test injects its own HttpRequest.
vi.mock("obsidian", () => ({
	requestUrl: vi.fn(),
	arrayBufferToBase64: (data: ArrayBuffer) => {
		const bytes = new Uint8Array(data);
		let binary = "";
		for (let i = 0; i < bytes.length; i++) {
			binary += String.fromCharCode(bytes[i]);
		}
		return btoa(binary);
	},
}));

const credentials: OAuth1Credentials = {
	consumerKey: "ck",
	consumerSecret: "cs",
	accessToken: "at",
	accessTokenSecret: "ats",
};

interface RecordedRequest {
	url: string;
	method: string;
	headers: Record<string, string>;
	body?: string;
}

// Fake transport: records every request and replays scripted responses in
// order. Tests assert on the recorded requests - the actual wire contract -
// never on client internals.
function scriptedHttp(responses: Array<{ status?: number; json?: unknown }>) {
	const requests: RecordedRequest[] = [];
	const queue = [...responses];
	const request: HttpRequest = async (req) => {
		requests.push(req);
		const next = queue.shift();
		if (!next) {
			throw new Error(`no scripted response left for ${req.method} ${req.url}`);
		}
		const json = next.json ?? null;
		const response: HttpResponse = {
			status: next.status ?? 200,
			text: JSON.stringify(json),
			json,
		};
		return response;
	};
	return { requests, request };
}

// HTTP header names are case-insensitive; don't fail on harmless casing.
function header(req: RecordedRequest, name: string): string | undefined {
	const key = Object.keys(req.headers).find((k) => k.toLowerCase() === name.toLowerCase());
	return key === undefined ? undefined : req.headers[key];
}

function jsonBody<T = unknown>(req: RecordedRequest): T {
	if (req.body === undefined) {
		throw new Error(`expected a JSON body on ${req.method} ${req.url}`);
	}
	return JSON.parse(req.body) as T;
}

describe("XApiClient", () => {
	describe("me", () => {
		it("GETs /2/users/me with an OAuth header and unwraps the user", async () => {
			const { requests, request } = scriptedHttp([
				{ json: { data: { id: "42", name: "Jane Doe", username: "jane" } } },
			]);
			const client = new XApiClient(credentials, request);

			const user = await client.me();

			expect(user).toEqual({ id: "42", name: "Jane Doe", username: "jane" });
			expect(requests).toHaveLength(1);
			expect(requests[0].method).toBe("GET");
			expect(requests[0].url).toBe("https://api.x.com/2/users/me");
			expect(header(requests[0], "Authorization")).toMatch(/^OAuth /);
		});
	});

	describe("createTweet", () => {
		it("POSTs the payload as JSON and returns the posted tweet", async () => {
			const payload: TweetPayload = {
				text: "hello from notetweet",
				media: { media_ids: ["m1", "m2"] },
				reply: { in_reply_to_tweet_id: "999" },
			};
			const { requests, request } = scriptedHttp([
				{ json: { data: { id: "111", text: "hello from notetweet" } } },
			]);
			const client = new XApiClient(credentials, request);

			const posted = await client.createTweet(payload);

			expect(posted).toEqual({ data: { id: "111", text: "hello from notetweet" } });
			expect(requests).toHaveLength(1);
			expect(requests[0].method).toBe("POST");
			expect(requests[0].url).toBe("https://api.x.com/2/tweets");
			expect(header(requests[0], "Content-Type")).toBe("application/json");
			expect(header(requests[0], "Authorization")).toMatch(/^OAuth /);
			// The body must round-trip to exactly the payload: media ids and
			// the reply target are what make image tweets and threads work.
			expect(jsonBody(requests[0])).toEqual(payload);
		});
	});

	describe("deleteTweet", () => {
		it("DELETEs /2/tweets/{id}", async () => {
			const { requests, request } = scriptedHttp([{ json: { data: { deleted: true } } }]);
			const client = new XApiClient(credentials, request);

			await client.deleteTweet("123");

			expect(requests).toHaveLength(1);
			expect(requests[0].method).toBe("DELETE");
			expect(requests[0].url).toBe("https://api.x.com/2/tweets/123");
		});
	});

	describe("uploadMedia", () => {
		it("uploads an image in one shot with the exact base64 payload", async () => {
			// PNG magic bytes plus 0x00/0xff: an encoder that routes the bytes
			// through UTF-8 instead of treating them as latin1 corrupts the
			// high bytes and this expected base64 stops matching.
			const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff]);
			const { requests, request } = scriptedHttp([{ json: { data: { id: "media-777" } } }]);
			const client = new XApiClient(credentials, request);

			const id = await client.uploadMedia(png.buffer, "image/png");

			expect(id).toBe("media-777");
			expect(requests).toHaveLength(1);
			expect(requests[0].method).toBe("POST");
			expect(requests[0].url).toBe("https://api.x.com/2/media/upload");
			const body = jsonBody<{ media: string; media_category: string; media_type: string }>(
				requests[0],
			);
			expect(body.media_category).toBe("tweet_image");
			expect(body.media_type).toBe("image/png");
			expect(body.media).toBe(Buffer.from(png).toString("base64"));
		});

		it("uploads a small GIF via initialize -> append -> finalize", async () => {
			const gif = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x00, 0xf9, 0x2c, 0x3b]);
			const { requests, request } = scriptedHttp([
				{ json: { data: { id: "gif-id-1" } } }, // initialize
				{ json: {} }, // append
				{ json: { data: { id: "gif-id-1" } } }, // finalize
			]);
			const client = new XApiClient(credentials, request);

			const id = await client.uploadMedia(gif.buffer, "image/gif");

			expect(id).toBe("gif-id-1");
			// The append/finalize URLs must embed the id returned by
			// initialize, not a hardcoded or stale one.
			expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual([
				"POST https://api.x.com/2/media/upload/initialize",
				"POST https://api.x.com/2/media/upload/gif-id-1/append",
				"POST https://api.x.com/2/media/upload/gif-id-1/finalize",
			]);
			expect(jsonBody(requests[0])).toMatchObject({
				media_type: "image/gif",
				media_category: "tweet_gif",
				total_bytes: gif.byteLength,
			});
			const append = jsonBody<{ media: string; segment_index: number }>(requests[1]);
			expect(append.segment_index).toBe(0);
			expect(append.media).toBe(Buffer.from(gif).toString("base64"));
			expect(requests[2].body).toBeUndefined();
		});

		it("splits GIF uploads into 1 MiB segments at the exact boundary", async () => {
			const MIB = 1024 * 1024;
			// 1 MiB + 3 bytes of a repeating pattern: forces exactly two
			// append segments, and the pattern lets us verify the second
			// segment carries the tail bytes rather than a re-read of the
			// start (a classic slice-offset bug).
			const big = new Uint8Array(MIB + 3);
			for (let i = 0; i < big.length; i++) {
				big[i] = i % 251;
			}
			const { requests, request } = scriptedHttp([
				{ json: { data: { id: "gif-big" } } }, // initialize
				{ json: {} }, // append segment 0
				{ json: {} }, // append segment 1
				{ json: { data: { id: "gif-big" } } }, // finalize
			]);
			const client = new XApiClient(credentials, request);

			const id = await client.uploadMedia(big.buffer, "image/gif");

			expect(id).toBe("gif-big");
			expect(requests.map((r) => `${r.method} ${r.url}`)).toEqual([
				"POST https://api.x.com/2/media/upload/initialize",
				"POST https://api.x.com/2/media/upload/gif-big/append",
				"POST https://api.x.com/2/media/upload/gif-big/append",
				"POST https://api.x.com/2/media/upload/gif-big/finalize",
			]);
			expect(jsonBody<{ total_bytes: number }>(requests[0]).total_bytes).toBe(MIB + 3);

			const first = jsonBody<{ media: string; segment_index: number }>(requests[1]);
			const second = jsonBody<{ media: string; segment_index: number }>(requests[2]);
			expect(first.segment_index).toBe(0);
			expect(second.segment_index).toBe(1);

			const firstBytes = Buffer.from(first.media, "base64");
			const secondBytes = Buffer.from(second.media, "base64");
			expect(firstBytes.length).toBe(MIB);
			expect(secondBytes.length).toBe(3);
			expect(firstBytes.equals(Buffer.from(big.subarray(0, MIB)))).toBe(true);
			expect(secondBytes.equals(Buffer.from(big.subarray(MIB)))).toBe(true);
		});
	});

	describe("error handling", () => {
		it("rejects with the extracted API error message on HTTP failures", async () => {
			const { request } = scriptedHttp([{ status: 403, json: { title: "Forbidden" } }]);
			const client = new XApiClient(credentials, request);

			const error = await client.createTweet({ text: "nope" }).then(
				() => {
					throw new Error("expected createTweet to reject");
				},
				(e: unknown) => e,
			);

			expect(error).toBeInstanceOf(Error);
			expect((error as Error).message).toBe("Forbidden");
		});
	});
});

describe("extractApiError", () => {
	// Priority order pinned: errors[0].message -> errors[0].detail -> title
	// -> detail -> HTTP <status>. X mixes these shapes across endpoints, so
	// a reshuffle silently downgrades every error message users see.
	const cases: Array<{ name: string; status: number; body: unknown; expected: string }> = [
		{
			name: "errors[0].message wins over title",
			status: 400,
			body: { errors: [{ message: "m" }], title: "t" },
			expected: "m",
		},
		{
			name: "errors[0].detail is used when message is absent",
			status: 400,
			body: { errors: [{ detail: "d" }] },
			expected: "d",
		},
		{
			name: "title wins over detail",
			status: 401,
			body: { title: "Unauthorized", detail: "bad token" },
			expected: "Unauthorized",
		},
		{
			name: "detail is used when title is absent",
			status: 400,
			body: { detail: "only detail" },
			expected: "only detail",
		},
		{
			name: "falls back to HTTP <status> for an empty body",
			status: 401,
			body: null,
			expected: "HTTP 401",
		},
	];

	for (const { name, status, body, expected } of cases) {
		it(name, () => {
			expect(extractApiError(status, body)).toBe(expected);
		});
	}
});
