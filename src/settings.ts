import {App, ButtonComponent, PluginSettingTab, Setting, TextComponent} from "obsidian";
import NoteTweet from "./main";
import { SecureModeModal } from "./Modals/SecureModeSettingModal/SecureModeModal";
import {ScheduledTweetsModal} from "./Modals/ScheduledTweetsModal";

export interface NoteTweetSettings {
  apiKey: string;
  apiSecret: string;
  accessToken: string;
  accessTokenSecret: string;
  postTweetTag: string;
  secureMode: boolean;
  autoSplitTweets: boolean;
  scheduling: {enabled: boolean, url: string, password: string, cronStrings: string[]};
}

export const DEFAULT_SETTINGS: NoteTweetSettings = Object.freeze({
  apiKey: "",
  apiSecret: "",
  accessToken: "",
  accessTokenSecret: "",
  postTweetTag: "",
  secureMode: false,
  autoSplitTweets: true,
  scheduling: {enabled: false, url: "", password: "", cronStrings: []},
});

export class NoteTweetSettingsTab extends PluginSettingTab {
  plugin: NoteTweet;
  private statusIndicator: HTMLElement;

  constructor(app: App, plugin: NoteTweet) {
    super(app, plugin);
    this.plugin = plugin;
  }

  checkStatus(message?: string) {
    if (message) {
      this.statusIndicator.innerHTML = `<strong>Plugin Status:</strong> ${message}`;
    } else {
      this.statusIndicator.innerHTML = `<strong>Plugin Status:</strong> ${
        this.plugin.twitterHandler.isConnectedToTwitter
          ? "✅ Plugin connected to Twitter."
          : "🛑 Plugin not connected to Twitter."
      }`;
    }
  }

  async updateConnectionStatus() {
    this.checkStatus("⏳ Verifying Twitter credentials...");
    const connected = await this.plugin.connectToTwitterWithPlainSettings();
    if (connected === undefined && this.plugin.settings.secureMode) {
      this.checkStatus("🔒 Secure mode enabled.");
    } else {
      this.checkStatus();
    }
  }

  display(): void {
    let { containerEl } = this;
    containerEl.empty();

    containerEl.createEl("h2", { text: "NoteTweet" });
    this.statusIndicator = containerEl.createEl("p");
    this.checkStatus();

    this.addApiKeySetting();
    this.addApiSecretSetting();
    this.addAccessTokenSetting();
    this.addAccessTokenSecretSetting();
    this.addTweetTagSetting();
    this.addAutoSplitTweetsSetting();
    this.addSecureModeSetting();
    this.addSchedulerSetting();
  }

  private addSecureModeSetting() {
    new Setting(this.containerEl)
      .setName("Secure Mode")
      .setDesc("Require password to unlock usage. Scheduler not supported.")
      .addToggle((toggle) =>
        toggle
          .setTooltip("Toggle Secure Mode")
          .setValue(this.plugin.settings.secureMode)
          .onChange(async (value) => {
            if (value == this.plugin.settings.secureMode) return;
            let secureModeModal = new SecureModeModal(
              this.app,
              this.plugin,
              value
            );

            await secureModeModal.waitForResolve;
            if (secureModeModal.userPressedCrypt) {
              this.plugin.settings.secureMode = value;
              await this.plugin.saveSettings();
              this.display();
            }

            toggle.setValue(this.plugin.settings.secureMode);
            this.display();
          })
      );
  }

  private addTweetTagSetting() {
    new Setting(this.containerEl)
      .setName("Tweet Tag")
      .setDesc("Appended to your tweets to indicate that it has been posted.")
      .addText((text) =>
        text
          .setPlaceholder("Tag to append")
          .setValue(this.plugin.settings.postTweetTag)
          .onChange(async (value) => {
            this.plugin.settings.postTweetTag = value;
            await this.plugin.saveSettings();
          })
      );
  }

  private addAccessTokenSecretSetting() {
    new Setting(this.containerEl)
      .setName("Access Token Secret")
      .setDesc("Twitter Access Token Secret.")
      .addText((text) => {
          this.setPasswordOnBlur(text.inputEl);
          text
              .setPlaceholder("Enter your Access Token Secret")
              .setValue(this.plugin.settings.accessTokenSecret)
              .onChange(async (value) => {
                  this.plugin.settings.accessTokenSecret = value;
                  await this.plugin.saveSettings();

                  await this.updateConnectionStatus();
              })
          }
      );
  }

  private addAccessTokenSetting() {
    new Setting(this.containerEl)
      .setName("Access Token")
      .setDesc("Twitter Access Token.")
      .addText((text) => {
          this.setPasswordOnBlur(text.inputEl);
          text
              .setPlaceholder("Enter your Access Token")
              .setValue(this.plugin.settings.accessToken)
              .onChange(async (value) => {
                  this.plugin.settings.accessToken = value;
                  await this.plugin.saveSettings();

                  await this.updateConnectionStatus();
              })
          }
      );
  }

  private addApiSecretSetting() {
    new Setting(this.containerEl)
      .setName("API Secret")
      .setDesc("Twitter API Secret.")
      .addText((text) => {
          this.setPasswordOnBlur(text.inputEl);
          text
              .setPlaceholder("Enter your API Secret")
              .setValue(this.plugin.settings.apiSecret)
              .onChange(async (value) => {
                  this.plugin.settings.apiSecret = value;
                  await this.plugin.saveSettings();

                  await this.updateConnectionStatus();
              })
          }
      );
  }

  private addApiKeySetting() {
    new Setting(this.containerEl)
      .setName("API Key")
      .setDesc("Twitter API key.")
      .addText((text) => {
          this.setPasswordOnBlur(text.inputEl);
          text
              .setPlaceholder("Enter your API key")
              .setValue(this.plugin.settings.apiKey)
              .onChange(async (value) => {
                  this.plugin.settings.apiKey = value;
                  await this.plugin.saveSettings();

                  await this.updateConnectionStatus();
              })
          }
      );
  }

    private addAutoSplitTweetsSetting() {
        new Setting(this.containerEl)
            .setName("Auto-split tweets")
            .setDesc("Automatically split tweets at 280 characters. Disable this to allow tweets to exceed character limit. Note: Posting tweets longer than 280 characters requires a paid X (Twitter) plan.")
            .addToggle(toggle => 
                toggle.setTooltip('Toggle auto-splitting tweets')
                    .setValue(this.plugin.settings.autoSplitTweets)
                    .onChange(async value => {
                        this.plugin.settings.autoSplitTweets = value;
                        await this.plugin.saveSettings();
                    })
            );
    }

    private addSchedulerSetting() {
        new Setting(this.containerEl)
            .setName("Scheduling")
            .setDesc("Enable scheduling tweets. This will require some setup!")
            .addToggle(toggle =>
                toggle.setTooltip('Toggle tweet scheduling')
                    .setValue(this.plugin.settings?.scheduling.enabled)
                    .onChange(async value => {
                        this.plugin.settings.scheduling.enabled = value;
                        await this.plugin.saveSettings();
                        this.display();
                    })
            );

        new Setting(this.containerEl)
            .setName('Scheduled tweets')
            .addButton(button => button
                .setButtonText("Open")
                .onClick(async () => {
                    new ScheduledTweetsModal(this.app, this.plugin.scheduler).open();
                }));

        if (this.plugin.settings?.scheduling.enabled) {
            new Setting(this.containerEl)
            .setName("Scheduler URL")
            .setDesc("Endpoint URL")
            .addText(text =>
                text.setPlaceholder("Scheduler URL")
                    .setValue(this.plugin.settings?.scheduling.url)
                    .onChange(async value => {
                        this.plugin.settings.scheduling.url = value;
                        await this.plugin.saveSettings();
                    })
            );

            new Setting(this.containerEl)
                .setName("Scheduler password")
                .setDesc("Password set for the scheduler")
                .addText(text => {
                    this.setPasswordOnBlur(text.inputEl);
                    text.setPlaceholder('Password')
                        .setValue(this.plugin.settings?.scheduling.password)
                        .onChange(async value => {
                            this.plugin.settings.scheduling.password = value;
                            await this.plugin.saveSettings();
                        })
                    }
                );

        }
    }

    private setPasswordOnBlur(el: HTMLInputElement) {
        el.addEventListener('focus', () => {
            el.type = "text";
        });

        el.addEventListener('blur', () => {
            el.type = "password";
        });

        el.type = "password";
    }
}
