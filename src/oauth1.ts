/**
 * Minimal OAuth 1.0a (RFC 5849) request signing with HMAC-SHA1, built on
 * WebCrypto so it runs on both Obsidian desktop and mobile. This replaces the
 * signing half of twitter-api-v2, whose Node-builtin usage made the plugin
 * desktop-only.
 */

export interface OAuth1Credentials {
	consumerKey: string;
	consumerSecret: string;
	accessToken: string;
	accessTokenSecret: string;
}

/** RFC 3986 strict percent-encoding (encodes !'()* too). */
export function percentEncode(value: string): string {
	// encodeURIComponent leaves !'()* alone, but RFC 5849 §3.6 requires them
	// escaped; a mismatch here breaks every signature.
	return encodeURIComponent(value).replace(
		/[!'()*]/g,
		(char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
	);
}

function randomNonce(): string {
	const bytes = new Uint8Array(16);
	crypto.getRandomValues(bytes);
	let hex = "";
	for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
	return hex;
}

function base64FromBytes(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary);
}

async function hmacSha1Base64(key: string, message: string): Promise<string> {
	const encoder = new TextEncoder();
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		encoder.encode(key),
		{ name: "HMAC", hash: "SHA-1" },
		false,
		["sign"],
	);
	const signature = await crypto.subtle.sign(
		"HMAC",
		cryptoKey,
		encoder.encode(message),
	);
	return base64FromBytes(new Uint8Array(signature));
}

/**
 * Builds the `Authorization: OAuth ...` header value for one request.
 * `params` are the request's query/form parameters that participate in the
 * signature base (JSON request bodies are NOT signed, per OAuth 1.0a).
 * `timestamp` (seconds) and `nonce` are injectable for deterministic tests;
 * defaults use Date.now() and crypto.getRandomValues.
 */
export async function oauth1Header(args: {
	method: string;
	url: string; // base URL without query string
	credentials: OAuth1Credentials;
	params?: Record<string, string>;
	timestamp?: number;
	nonce?: string;
}): Promise<string> {
	const { method, url, credentials, params = {} } = args;
	const timestamp = args.timestamp ?? Math.floor(Date.now() / 1000);
	const nonce = args.nonce ?? randomNonce();

	const oauthParams: Record<string, string> = {
		oauth_consumer_key: credentials.consumerKey,
		oauth_nonce: nonce,
		oauth_signature_method: "HMAC-SHA1",
		oauth_timestamp: String(timestamp),
		oauth_token: credentials.accessToken,
		oauth_version: "1.0",
	};

	// RFC 5849 §3.4.1.3.2: encode every key and value FIRST, then sort by
	// encoded key (encoded value breaks ties), then join `k=v` with `&`.
	const paramString = [...Object.entries(params), ...Object.entries(oauthParams)]
		.map(([key, value]) => [percentEncode(key), percentEncode(value)] as const)
		.sort(([keyA, valueA], [keyB, valueB]) => {
			// Byte-wise order; encoded params are pure ASCII so `<` is exact.
			const a = keyA === keyB ? valueA : keyA;
			const b = keyA === keyB ? valueB : keyB;
			return a < b ? -1 : a > b ? 1 : 0;
		})
		.map(([key, value]) => `${key}=${value}`)
		.join("&");

	const baseString = [
		method.toUpperCase(),
		percentEncode(url),
		percentEncode(paramString),
	].join("&");
	const signingKey = `${percentEncode(credentials.consumerSecret)}&${percentEncode(
		credentials.accessTokenSecret,
	)}`;
	const signature = await hmacSha1Base64(signingKey, baseString);

	// Only the oauth_* protocol params go in the header; request params stay
	// in the query string / body where they already live.
	const headerParams: Record<string, string> = {
		...oauthParams,
		oauth_signature: signature,
	};
	const header = Object.keys(headerParams)
		.sort()
		.map((key) => `${percentEncode(key)}="${percentEncode(headerParams[key])}"`)
		.join(", ");
	return `OAuth ${header}`;
}
