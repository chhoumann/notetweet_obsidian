import { App } from "obsidian";
import { ThreadPostError, TwitterClient } from "./twitter";
import type { HttpRequest } from "./xApi";

const credentials = {
	apiKey: "ak",
	apiSecret: "as",
	accessToken: "at",
	accessTokenSecret: "ats",
};

function respond(status: number, json: unknown) {
	return { status, text: JSON.stringify(json), json };
}

describe("TwitterClient.postThread", () => {
	it("reports the tweets already live when a later tweet fails", async () => {
		const request = vi
			.fn<HttpRequest>()
			.mockResolvedValueOnce(respond(200, { data: { id: "me", name: "Me", username: "me" } }))
			.mockResolvedValueOnce(respond(200, { data: { id: "1", text: "first" } }))
			.mockResolvedValueOnce(respond(429, { title: "Too Many Requests" }));
		const client = new TwitterClient(new App(), request);
		await client.connect(credentials);

		const error = await client.postThread(["first", "second"]).catch((e: unknown) => e);

		expect(error).toBeInstanceOf(ThreadPostError);
		expect((error as ThreadPostError).posted.map((tweet) => tweet.data.id)).toEqual(["1"]);
	});
});
