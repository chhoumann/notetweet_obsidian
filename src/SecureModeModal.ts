import {App, Modal} from "obsidian";
import NoteTweet from "./main";
import CryptoES from "crypto-es";

export class SecureModeModal extends Modal {
    private _plugin: NoteTweet;
    private _enable: boolean;

    constructor(app: App, plugin: NoteTweet, enable: boolean) {
        super(app);
        this._plugin = plugin;
        this._enable = enable;
    }

    onOpen() {
        let {contentEl} = this;

        contentEl.createEl("h1", {text: "Secure Mode Settings"});
        contentEl.createEl("p", {text: "Please enter your password below and then click the button below."})
        let passwordInput = contentEl.createEl("input", {type: "password"});
        let hashButton = contentEl.createEl("button", {text: `${this._enable ? "Encrypt!" : "Decrypt!"}`});
        hashButton.style.marginLeft = "1rem";

        hashButton.addEventListener("click", async () => {
            let password = passwordInput.value;

            this._enable ? await this.encryptKeysWithPassword(password) : await this.decryptKeysWithPassword(password);
        })

        contentEl.createEl("h2", {text: "What is this?"}).style.marginBottom = "0.5rem";
        let explanation = contentEl.createEl("p");
        explanation.innerHTML = `Secure Mode enables you to encrypt your API keys with a password.<br>` +
            `The password will be required to use the plugin - until you disable Secure Mode.<br>` +
            `Your API keys will remain stored - but encrypted.<br>` +
            `That means they will be unintelligible to anyone who doesn't know your password.<br>` +
            `<strong>Please do note that this plugin cannot check if your passwords decrypts your keys correctly!</strong><br>` +
            `<strong>This means you might have to re-enter your keys if they decrypt incorrectly.</strong>`;
    }

    onClose() {
        let {contentEl} = this;
        contentEl.empty();
    }

    private async encryptKeysWithPassword(password: string) {
        this._plugin.settings.apiKey = CryptoES.AES.encrypt(this._plugin.settings.apiKey, password).toString();
        this._plugin.settings.apiSecret = CryptoES.AES.encrypt(this._plugin.settings.apiSecret, password).toString();
        this._plugin.settings.accessToken = CryptoES.AES.encrypt(this._plugin.settings.accessToken, password).toString();
        this._plugin.settings.accessTokenSecret = CryptoES.AES.encrypt(this._plugin.settings.accessTokenSecret, password).toString();

        await this._plugin.saveSettings();
    }

    private async decryptKeysWithPassword(password: string) {
        this._plugin.settings.apiKey = CryptoES.AES.decrypt(this._plugin.settings.apiKey, password).toString(CryptoES.enc.Utf8);
        this._plugin.settings.apiSecret = CryptoES.AES.decrypt(this._plugin.settings.apiSecret, password).toString(CryptoES.enc.Utf8);
        this._plugin.settings.accessToken = CryptoES.AES.decrypt(this._plugin.settings.accessToken, password).toString(CryptoES.enc.Utf8);
        this._plugin.settings.accessTokenSecret = CryptoES.AES.decrypt(this._plugin.settings.accessTokenSecret, password).toString(CryptoES.enc.Utf8);

        await this._plugin.saveSettings();
    }
}