import {App, PluginSettingTab, Setting} from "obsidian";
import NoteTweet from "./main";
import {SecureModeModal} from "./Modals/SecureModeModal";

export interface NoteTweetSettings {
    apiKey: string,
    apiSecret: string,
    accessToken: string,
    accessTokenSecret: string,
    postTweetTag: string,
    secureMode: boolean,
}

export const DEFAULT_SETTINGS: NoteTweetSettings = Object.freeze({
    apiKey: '',
    apiSecret: '',
    accessToken: '',
    accessTokenSecret: '',
    postTweetTag: '',
    secureMode: false,
});

export class NoteTweetSettingsTab extends PluginSettingTab {
    plugin: NoteTweet;
    private statusIndicator: HTMLElement;

    constructor(app: App, plugin: NoteTweet) {
        super(app, plugin);
        this.plugin = plugin;
    }

    checkStatus() {
        this.statusIndicator.innerHTML =
            `<strong>Plugin Status:</strong> ${this.plugin.twitterHandler.isConnectedToTwitter ?
                "✅ Plugin connected to Twitter." : "🛑 Plugin not connected to Twitter."}`;
    }

    display(): void {
        let {containerEl} = this;
        containerEl.empty();

        containerEl.createEl('h2', {text: 'NoteTweet'});
        this.statusIndicator = containerEl.createEl("p");
        this.checkStatus();

        this.addApiKeySetting();
        this.addApiSecretSetting();
        this.addAccessTokenSetting();
        this.addAccessTokenSecretSetting();
        this.addTweetTagSetting();
        this.addSecureModeSetting();

    }

    private addSecureModeSetting() {
        new Setting(this.containerEl)
            .setName('Secure Mode')
            .setDesc('Require password to unlock usage.')
            .addToggle(toggle => toggle
                .setTooltip('Toggle Secure Mode')
                .setValue(this.plugin.settings.secureMode)
                .onChange(async value => {
                    this.plugin.settings.secureMode = value;
                    await this.plugin.saveSettings();

                    new SecureModeModal(this.app, this.plugin, value).open();
                })
            )
    }

    private addTweetTagSetting() {
        new Setting(this.containerEl)
            .setName('Tweet Tag')
            .setDesc('Appended to your tweets to indicate that it has been posted.')
            .addText(text => text
                .setPlaceholder('Tag to append')
                .setValue(this.plugin.settings.postTweetTag)
                .onChange(async (value) => {
                    this.plugin.settings.postTweetTag = value;
                    await this.plugin.saveSettings();
                })
            )
    }

    private addAccessTokenSecretSetting() {
        new Setting(this.containerEl)
            .setName('Access Token Secret')
            .setDesc('Twitter Access Token Secret.')
            .addText(text => text
                .setPlaceholder('Enter your Access Token Secret')
                .setValue(this.plugin.settings.accessTokenSecret)
                .onChange(async (value) => {
                    this.plugin.settings.accessTokenSecret = value;
                    await this.plugin.saveSettings();

                    this.plugin.connectToTwitterWithPlainSettings();
                    this.checkStatus();
                }));
    }

    private addAccessTokenSetting() {
        new Setting(this.containerEl)
            .setName('Access Token')
            .setDesc('Twitter Access Token.')
            .addText(text => text
                .setPlaceholder('Enter your Access Token')
                .setValue(this.plugin.settings.accessToken)
                .onChange(async (value) => {
                    this.plugin.settings.accessToken = value;
                    await this.plugin.saveSettings();

                    this.plugin.connectToTwitterWithPlainSettings();
                    this.checkStatus();
                }));
    }

    private addApiSecretSetting() {
        new Setting(this.containerEl)
            .setName('API Secret')
            .setDesc('Twitter API Secret.')
            .addText(text => text
                .setPlaceholder('Enter your API Secret')
                .setValue(this.plugin.settings.apiSecret)
                .onChange(async (value) => {
                    this.plugin.settings.apiSecret = value;
                    await this.plugin.saveSettings();

                    this.plugin.connectToTwitterWithPlainSettings();
                    this.checkStatus();
                }));
    }

    private addApiKeySetting() {
        new Setting(this.containerEl)
            .setName('API Key')
            .setDesc('Twitter API key.')
            .addText(text => text
                .setPlaceholder('Enter your API key')
                .setValue(this.plugin.settings.apiKey)
                .onChange(async (value) => {
                    this.plugin.settings.apiKey = value;
                    await this.plugin.saveSettings();

                    this.plugin.connectToTwitterWithPlainSettings();
                    this.checkStatus();
                }));
    }
}