import { oauth1Header, percentEncode } from "./oauth1";
import type { OAuth1Credentials } from "./oauth1";

// Credentials from Twitter's published "Creating a signature" worked example.
// Every value below is pinned to that doc: if any part of the signing
// pipeline drifts (strict percent-encoding, param sorting, base-string
// assembly, HMAC-SHA1 keying), the signature stops matching and every real
// API call would 401.
const credentials: OAuth1Credentials = {
	consumerKey: "xvz1evFS4wEEPTGEFPHBog",
	consumerSecret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
	accessToken: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
	accessTokenSecret: "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
};

const canonicalRequest = {
	method: "POST",
	params: {
		include_entities: "true",
		status: "Hello Ladies + Gentlemen, a signed OAuth request!",
	},
	credentials,
	timestamp: 1318622958,
	nonce: "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
};

describe("oauth1Header", () => {
	// The widely-cited tnnArxj... signature is only correct for the 2011-era
	// /1/ URL. Later revisions of the same doc page changed the URL (first to
	// api.twitter.com/1.1, then to api.x.com/1.1) without republishing the
	// nonce/timestamp, so each URL has its own expected signature. All three
	// were cross-verified against two independent implementations; pinning
	// all of them guards the signer regardless of which doc revision anyone
	// consults later.
	it("reproduces Twitter's canonical signature vector", async () => {
		const header = await oauth1Header({
			...canonicalRequest,
			url: "https://api.twitter.com/1/statuses/update.json",
		});

		expect(header.startsWith("OAuth ")).toBe(true);
		// Percent-encoded form of base64 tnnArxj06cWHq44gCs1OSKk/jLY=
		expect(header).toContain('oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D"');
		expect(header).toContain('oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog"');
		expect(header).toContain('oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"');
		expect(header).toContain('oauth_signature_method="HMAC-SHA1"');
		expect(header).toContain('oauth_timestamp="1318622958"');
		expect(header).toContain('oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"');
		expect(header).toContain('oauth_version="1.0"');
	});

	const urlVariants: Array<{ name: string; url: string; signature: string }> = [
		{
			name: "the api.twitter.com/1.1 doc revision",
			url: "https://api.twitter.com/1.1/statuses/update.json",
			// Percent-encoded form of base64 hCtSmYh+iHYCEqBWrE7C7hYmtUk=
			signature: 'oauth_signature="hCtSmYh%2BiHYCEqBWrE7C7hYmtUk%3D"',
		},
		{
			name: "the api.x.com/1.1 doc revision (production host)",
			url: "https://api.x.com/1.1/statuses/update.json",
			// Percent-encoded form of base64 Ls93hJiZbQ3akF3HF3x1Bz8/zU4=
			signature: 'oauth_signature="Ls93hJiZbQ3akF3HF3x1Bz8%2FzU4%3D"',
		},
	];

	for (const { name, url, signature } of urlVariants) {
		it(`reproduces the signature for ${name}`, async () => {
			const header = await oauth1Header({ ...canonicalRequest, url });

			expect(header).toContain(signature);
		});
	}

	it("keeps request params in the signature base only, never in the header", async () => {
		const header = await oauth1Header({
			...canonicalRequest,
			url: "https://api.twitter.com/1/statuses/update.json",
		});

		// Leaking request params into the Authorization header would make X
		// reject the request even though the signature itself is valid.
		expect(header).not.toContain("status");
		expect(header).not.toContain("include_entities");
	});

	it("generates a fresh nonce for every call when none is injected", async () => {
		const args = {
			method: "GET",
			url: "https://api.x.com/2/users/me",
			credentials,
		};
		const first = await oauth1Header(args);
		const second = await oauth1Header(args);

		// Compare nonces rather than whole headers: two calls in the same
		// second share a timestamp, so a constant nonce would otherwise only
		// be caught when the calls happen to straddle a second boundary.
		const nonceOf = (header: string) => /oauth_nonce="([^"]+)"/.exec(header)?.[1];
		const firstNonce = nonceOf(first);
		const secondNonce = nonceOf(second);
		expect(firstNonce).toBeTruthy();
		expect(secondNonce).toBeTruthy();
		expect(firstNonce).not.toBe(secondNonce);
	});
});

describe("percentEncode", () => {
	it("encodes the canonical status string with the RFC 3986 strict set", () => {
		expect(percentEncode("Hello Ladies + Gentlemen, a signed OAuth request!")).toBe(
			"Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21",
		);
	});

	it("encodes the characters encodeURIComponent leaves bare", () => {
		// A naive encodeURIComponent-based encoder passes these through
		// unescaped, which corrupts the signature base whenever a tweet
		// contains them.
		expect(percentEncode("!'()*")).toBe("%21%27%28%29%2A");
	});

	it("passes unreserved characters through unchanged", () => {
		expect(percentEncode("Az0-9-._~")).toBe("Az0-9-._~");
	});
});
