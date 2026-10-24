/**
 * Decrypts values that were encrypted by the old "Secure Mode" feature
 * (crypto-es `AES.encrypt(value, password)`). Retained solely so existing users
 * can migrate their secure-mode credentials into Obsidian's SecretStorage
 * without re-entering them. Nothing writes new encrypted values anymore.
 *
 * The format is OpenSSL's `Salted__` envelope: base64 of "Salted__", an 8-byte
 * salt, then AES-256-CBC ciphertext, with key and IV derived by EVP_BytesToKey
 * (one MD5 iteration). Rejects when the password is wrong.
 */
export async function decryptLegacyValue(
	value: string,
	password: string,
): Promise<string> {
	const raw = Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
	if (new TextDecoder().decode(raw.subarray(0, 8)) !== "Salted__")
		throw new Error("Not a Secure Mode ciphertext");

	const salt = raw.subarray(8, 16);
	const passwordBytes = new TextEncoder().encode(password);
	const derived = new Uint8Array(48);
	let block = new Uint8Array(0);
	for (let offset = 0; offset < derived.length; offset += 16) {
		block = md5(concat(block, passwordBytes, salt));
		derived.set(block, offset);
	}

	const key = await crypto.subtle.importKey(
		"raw",
		derived.subarray(0, 32),
		"AES-CBC",
		false,
		["decrypt"],
	);
	const plaintext = await crypto.subtle.decrypt(
		{ name: "AES-CBC", iv: derived.subarray(32, 48) },
		key,
		raw.subarray(16),
	);
	return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
	let offset = 0;
	for (const part of parts) {
		out.set(part, offset);
		offset += part.length;
	}
	return out;
}

const MD5_SHIFTS = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const MD5_CONSTANTS = Array.from(
	{ length: 64 },
	(_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0,
);

// RFC 1321. WebCrypto has no MD5, and EVP_BytesToKey needs it.
function md5(input: Uint8Array): Uint8Array<ArrayBuffer> {
	const padded = new Uint8Array((((input.length + 8) >>> 6) + 1) * 64);
	padded.set(input);
	padded[input.length] = 0x80;
	const words = new DataView(padded.buffer);
	words.setUint32(padded.length - 8, (input.length * 8) >>> 0, true);
	words.setUint32(padded.length - 4, Math.floor((input.length * 8) / 2 ** 32), true);

	const state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
	for (let chunk = 0; chunk < padded.length; chunk += 64) {
		let [a, b, c, d] = state;
		for (let i = 0; i < 64; i++) {
			let f: number;
			let g: number;
			if (i < 16) {
				f = (b & c) | (~b & d);
				g = i;
			} else if (i < 32) {
				f = (d & b) | (~d & c);
				g = (5 * i + 1) % 16;
			} else if (i < 48) {
				f = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			} else {
				f = c ^ (b | ~d);
				g = (7 * i) % 16;
			}
			const sum = (a + f + MD5_CONSTANTS[i] + words.getUint32(chunk + g * 4, true)) | 0;
			const shift = MD5_SHIFTS[(i >>> 4) * 4 + (i % 4)];
			a = d;
			d = c;
			c = b;
			b = (b + ((sum << shift) | (sum >>> (32 - shift)))) | 0;
		}
		state[0] = (state[0] + a) | 0;
		state[1] = (state[1] + b) | 0;
		state[2] = (state[2] + c) | 0;
		state[3] = (state[3] + d) | 0;
	}

	const digest = new Uint8Array(16);
	const digestView = new DataView(digest.buffer);
	state.forEach((word, i) => digestView.setUint32(i * 4, word, true));
	return digest;
}
