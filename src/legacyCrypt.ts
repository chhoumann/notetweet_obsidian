import { AES, Utf8 } from "crypto-es";

/**
 * Decrypts values that were encrypted by the old "Secure Mode" feature
 * (AES via crypto-es). Retained solely so existing users can migrate their
 * secure-mode credentials into Obsidian's SecretStorage without re-entering
 * them. Nothing writes new encrypted values anymore.
 */
export function decryptLegacyValue(value: string, password: string): string {
	return AES.decrypt(value, password).toString(Utf8);
}
