import CryptoES from "crypto-es";

export class SecureModeCrypt {
  public static encryptString(string: string, key: string) {
    return CryptoES.AES.encrypt(string, key).toString();
  }
  public static decryptString(string: string, key: string) {
    return CryptoES.AES.decrypt(string, key).toString(CryptoES.enc.Utf8);
  }
}
