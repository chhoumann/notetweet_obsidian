import {App, Modal, Notice} from "obsidian";
import NoteTweet from "./main";
import CryptoES from "crypto-es";

export class SecureModeGetPasswordModal extends Modal {
    private _plugin: NoteTweet;
    private callback: any;

    constructor(app: App, plugin: NoteTweet) {
        super(app);
        this._plugin = plugin;
    }

    onOpen() {
        let {contentEl} = this;

        contentEl.createEl("h2", {text: "Secure Mode"});
        contentEl.createEl("p", {text: "Please enter your password to continue:"})
        let passwordInput = contentEl.createEl("input", {type: "password"});
        let submitButton = contentEl.createEl("button", {text: "Submit"});
        submitButton.addEventListener("click", () => {
            if (passwordInput.value === "")
                return;

            this.secureModeLogin(passwordInput.value);

            if (this._plugin.isReady) {
                new Notice("Successfully authenticated with Twitter!");
                this.close();
            }
        })
    }

    private secureModeLogin(password: string) {
        this._plugin.connectToTwitter(
            CryptoES.AES.decrypt(this._plugin.settings.apiKey, password).toString(CryptoES.enc.Utf8),
            CryptoES.AES.decrypt(this._plugin.settings.apiSecret, password).toString(CryptoES.enc.Utf8),
            CryptoES.AES.decrypt(this._plugin.settings.accessToken, password).toString(CryptoES.enc.Utf8),
            CryptoES.AES.decrypt(this._plugin.settings.accessTokenSecret, password).toString(CryptoES.enc.Utf8)
        );
    }

    onClose() {
        let {contentEl} = this;
        contentEl.empty();
    }
}