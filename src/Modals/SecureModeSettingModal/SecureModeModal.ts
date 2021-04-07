import { App, Modal } from "obsidian";
import NoteTweet from "../../main";
import { SecureModeCrypt } from "../../SecureModeCrypt";
import SecureModeSettingModalContent from "./SecureModeSettingModalContent.svelte";
import set = Reflect.set;

export class SecureModeModal extends Modal {
  private plugin: NoteTweet;
  private readonly enable: boolean;
  private resolvePromise: () => void;
  private secureModeSettingModalContent: SecureModeSettingModalContent;
  public waitForResolve: Promise<void>;
  public userPressedCrypt: boolean = false;

  constructor(app: App, plugin: NoteTweet, enable: boolean) {
    super(app);
    this.plugin = plugin;
    this.enable = enable;

    this.waitForResolve = new Promise<void>(
      (resolve) => (this.resolvePromise = resolve)
    );

    this.secureModeSettingModalContent = new SecureModeSettingModalContent({
      target: this.contentEl,
      props: {
        enable: this.enable,
        userPressedCrypt: this.userPressedCrypt,
        onSubmit: (value: string) => this.onSubmit(value),
      },
    });

    this.open();
  }

  private async onSubmit(value: string) {
    this.enable
      ? await this.encryptKeysWithPassword(value)
      : await this.decryptKeysWithPassword(value);

    this.userPressedCrypt = true;

    this.close();
  }

  onClose() {
    super.onClose();
    this.secureModeSettingModalContent.$destroy();
    this.resolvePromise();
  }

  private async encryptKeysWithPassword(password: string) {
    this.plugin.settings.apiKey = SecureModeCrypt.encryptString(
      this.plugin.settings.apiKey,
      password
    );
    this.plugin.settings.apiSecret = SecureModeCrypt.encryptString(
      this.plugin.settings.apiSecret,
      password
    );
    this.plugin.settings.accessToken = SecureModeCrypt.encryptString(
      this.plugin.settings.accessToken,
      password
    );
    this.plugin.settings.accessTokenSecret = SecureModeCrypt.encryptString(
      this.plugin.settings.accessTokenSecret,
      password
    );

    await this.plugin.saveSettings();
  }

  private async decryptKeysWithPassword(password: string) {
    this.plugin.settings.apiKey = SecureModeCrypt.decryptString(
      this.plugin.settings.apiKey,
      password
    );
    this.plugin.settings.apiSecret = SecureModeCrypt.decryptString(
      this.plugin.settings.apiSecret,
      password
    );
    this.plugin.settings.accessToken = SecureModeCrypt.decryptString(
      this.plugin.settings.accessToken,
      password
    );
    this.plugin.settings.accessTokenSecret = SecureModeCrypt.decryptString(
      this.plugin.settings.accessTokenSecret,
      password
    );

    await this.plugin.saveSettings();
  }
}
