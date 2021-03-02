import {App, PluginSettingTab, Setting} from "obsidian";
import NoteTweet from "./main";
import {SecureModeModal} from "./SecureModeModal";
import {EventsNew} from "twitter-api-client";

export class NoteTweetSettingsTab extends PluginSettingTab {
    plugin: NoteTweet;

    constructor(app: App, plugin: NoteTweet) {
        super(app, plugin);
        this.plugin = plugin;
    }

    display(): void {
        let {containerEl} = this;

        containerEl.empty();

        containerEl.createEl('h2', {text: 'NoteTweet'});
        let statusIndicator = containerEl.createEl("p");
        this.checkStatus(statusIndicator);

        new Setting(containerEl)
            .setName('API Key')
            .setDesc('Twitter API key.')
            .addText(text => text
                .setPlaceholder('Enter your API key')
                .setValue(this.plugin.settings.apiKey)
                .onChange(async (value) => {
                    this.plugin.settings.apiKey = value;
                    await this.plugin.saveSettings();

                    this.attemptConnect();
                    this.checkStatus(statusIndicator);
                }));

        new Setting(containerEl)
            .setName('API Secret')
            .setDesc('Twitter API Secret.')
            .addText(text => text
                .setPlaceholder('Enter your API Secret')
                .setValue(this.plugin.settings.apiSecret)
                .onChange(async (value) => {
                    this.plugin.settings.apiSecret = value;
                    await this.plugin.saveSettings();

                    this.attemptConnect();
                    this.checkStatus(statusIndicator);
                }));

        new Setting(containerEl)
            .setName('Access Token')
            .setDesc('Twitter Access Token.')
            .addText(text => text
                .setPlaceholder('Enter your Access Token')
                .setValue(this.plugin.settings.accessToken)
                .onChange(async (value) => {
                    this.plugin.settings.accessToken = value;
                    await this.plugin.saveSettings();

                    this.attemptConnect();
                    this.checkStatus(statusIndicator);
                }));

        new Setting(containerEl)
            .setName('Access Token Secret')
            .setDesc('Twitter Access Token Secret.')
            .addText(text => text
                .setPlaceholder('Enter your Access Token Secret')
                .setValue(this.plugin.settings.accessTokenSecret)
                .onChange(async (value) => {
                    this.plugin.settings.accessTokenSecret = value;
                    await this.plugin.saveSettings();

                    this.attemptConnect();
                    this.checkStatus(statusIndicator);
                }));

        new Setting(containerEl)
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

        new Setting(containerEl)
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

    private attemptConnect() {
        let {apiKey, apiSecret, accessToken, accessTokenSecret} = this.plugin.settings;
        this.plugin.connectToTwitter(apiKey, apiSecret, accessToken, accessTokenSecret);
    }

    checkStatus(statusIndicator: any) {
        statusIndicator.innerHTML =
            `<strong>Plugin Status:</strong> ${this.plugin.isReady ?
                "✅ Plugin connected to Twitter." : "🛑 Plugin not connected to Twitter."}`;
    }
}