import {App, Modal, Notice} from "obsidian";
import NoteTweet from "../main";
import {SecureModeCrypt} from '../SecureModeCrypt'

export class SecureModeGetPasswordModal extends Modal {
    public isOpen: boolean;

    private _plugin: NoteTweet;

    constructor(app: App, plugin: NoteTweet) {
        super(app);
        this._plugin = plugin;
    }

    onOpen() {
        let {contentEl} = this;
        this.isOpen = true;

        contentEl.createEl("h2", {text: "Secure Mode"});
        contentEl.createEl("p", {text: "Please enter your password to continue:"})
        let passwordInput = contentEl.createEl("input", {type: "password"});
        let submitButton = contentEl.createEl("button", {text: "Submit"});
        submitButton.addEventListener("click", () => {
            if (passwordInput.value === "")
                return;

            try {
                this.secureModeLogin(passwordInput.value);
            }
            catch (e) {
                new Notice("Wrong password.");
            }

            if (this._plugin.twitterHandler.isConnectedToTwitter) {
                new Notice("Successfully authenticated with Twitter!");
                this.close();
            }
        })
    }

    private secureModeLogin(password: string) {
        this._plugin.twitterHandler.connectToTwitter(
            SecureModeCrypt.decryptString(this._plugin.settings.apiKey, password),
            SecureModeCrypt.decryptString(this._plugin.settings.apiSecret, password),
            SecureModeCrypt.decryptString(this._plugin.settings.accessToken, password),
            SecureModeCrypt.decryptString(this._plugin.settings.accessTokenSecret, password)
        );
    }

    onClose() {
        let {contentEl} = this;
        contentEl.empty();
        this.isOpen = false;
    }
}