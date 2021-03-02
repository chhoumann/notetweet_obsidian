import {App, PluginSettingTab, Setting} from "obsidian";
import NoteTweet from "./main";

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

        new Setting(containerEl)
            .setName('API Key')
            .setDesc('Twitter API key.')
            .addText(text => text
                .setPlaceholder('Enter your API key')
                .setValue(this.plugin.settings.APIKey)
                .onChange(async (value) => {
                    this.plugin.settings.APIKey = value;
                    await this.plugin.saveSettings();
                }));

        new Setting(containerEl)
            .setName('API Secret')
            .setDesc('Twitter API Secret.')
            .addText(text => text
                .setPlaceholder('Enter your API Secret')
                .setValue(this.plugin.settings.APISecret)
                .onChange(async (value) => {
                    this.plugin.settings.APISecret = value;
                    await this.plugin.saveSettings();
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
    }
}