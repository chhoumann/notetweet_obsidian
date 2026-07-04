import {
	type App,
	Notice,
	PluginSettingTab,
	type Setting,
	type SettingDefinition,
	type SettingDefinitionGroup,
	type SettingDefinitionItem,
} from "obsidian";
import type NoteTweet from "./main";
import { log } from "./log";
import {
	SECRET_IDS,
	type SecretId,
	getSecret,
	hasSecretStorage,
	setSecret,
} from "./secrets";
import {
	type LegacyCredentialData,
	legacyCredentialsEncrypted,
	legacyCredentialsPresent,
	readLegacyCredentials,
	stripLegacyCredentials,
	storeCredentials,
} from "./migration";
import { InputPromptModal } from "./Modals/InputPromptModal";
import { ScheduledTweetsModal } from "./Modals/ScheduledTweetsModal";

const RECONNECT_DELAY_MS = 800;

/**
 * Declarative settings tab (Obsidian 1.13 API). Non-secret settings are plain
 * `control` definitions round-tripped through {@link getControlValue} /
 * {@link setControlValue}; credentials use masked `render` rows backed by
 * SecretStorage; a migration group appears only while legacy credentials linger
 * in the plugin's data file.
 */
export class NoteTweetSettingsTab extends PluginSettingTab {
	private statusEl: HTMLElement | null = null;
	private reconnectTimer: number | null = null;

	constructor(app: App, private readonly noteTweet: NoteTweet) {
		super(app, noteTweet);
	}

	override getControlValue(key: string): unknown {
		const settings = this.noteTweet.settings;
		switch (key) {
			case "postTweetTag":
				return settings.postTweetTag;
			case "autoSplitTweets":
				return settings.autoSplitTweets;
			case "scheduling.enabled":
				return settings.scheduling.enabled;
			case "scheduling.url":
				return settings.scheduling.url;
			default:
				return undefined;
		}
	}

	override async setControlValue(key: string, value: unknown): Promise<void> {
		const settings = this.noteTweet.settings;
		switch (key) {
			case "postTweetTag":
				settings.postTweetTag = String(value);
				break;
			case "autoSplitTweets":
				settings.autoSplitTweets = Boolean(value);
				break;
			case "scheduling.enabled":
				settings.scheduling.enabled = Boolean(value);
				await this.noteTweet.saveSettings();
				this.noteTweet.refreshScheduler();
				this.refreshDomState();
				return;
			case "scheduling.url":
				settings.scheduling.url = String(value);
				await this.noteTweet.saveSettings();
				this.noteTweet.refreshScheduler();
				return;
			default:
				return;
		}
		await this.noteTweet.saveSettings();
	}

	override getSettingDefinitions(): SettingDefinitionItem[] {
		return [
			this.migrationGroup(),
			this.credentialsGroup(),
			this.postingGroup(),
			this.schedulingGroup(),
		];
	}

	private migrationGroup(): SettingDefinitionGroup {
		return {
			type: "group",
			heading: "Migrate credentials",
			visible: () =>
				legacyCredentialsPresent(this.legacyData()) && hasSecretStorage(this.app),
			items: [
				{
					name: "Move credentials to secure storage",
					desc: "Your Twitter credentials are still stored in this vault's plugin data. Move them into Obsidian's encrypted secret storage.",
					render: (setting: Setting) => {
						setting.addButton((button) =>
							button
								.setButtonText("Migrate now")
								.setCta()
								.onClick(() => this.migrate()),
						);
					},
				},
			],
		};
	}

	private credentialsGroup(): SettingDefinitionGroup {
		return {
			type: "group",
			heading: "X API credentials",
			items: [
				{
					name: "Secret storage unavailable",
					desc: "This version of Obsidian does not support secret storage, so credentials cannot be stored securely. Update Obsidian to use NoteTweet.",
					visible: () => !hasSecretStorage(this.app),
				},
				{
					name: "Connection",
					searchable: false,
					render: (setting: Setting) => {
						this.statusEl = setting.controlEl.createSpan();
						this.refreshStatus();
					},
				},
				this.secretRow(
					"API key",
					SECRET_IDS.apiKey,
					"Enter your API key",
					"Your app's API Key (also called the Consumer Key), from Keys and tokens in the X developer portal.",
				),
				this.secretRow(
					"API secret",
					SECRET_IDS.apiSecret,
					"Enter your API secret",
					"Your app's API Key Secret (the Consumer Secret).",
				),
				this.secretRow(
					"Access token",
					SECRET_IDS.accessToken,
					"Enter your access token",
					"Generate under Keys and tokens -> Access Token and Secret (requires Read and Write user authentication).",
				),
				this.secretRow(
					"Access token secret",
					SECRET_IDS.accessTokenSecret,
					"Enter your access token secret",
					"The Access Token Secret shown when you generate the access token.",
				),
			],
		};
	}

	private postingGroup(): SettingDefinitionGroup {
		return {
			type: "group",
			heading: "Posting",
			items: [
				{
					name: "Tweet tag",
					desc: "Appended to your note after a tweet is posted, marking it as tweeted. Leave empty to disable.",
					control: { type: "text", key: "postTweetTag", placeholder: "#tweeted" },
				},
				{
					name: "Auto-split tweets",
					desc: "Split content into multiple tweets at 280 characters. Disable to allow longer tweets (requires a paid X plan).",
					control: { type: "toggle", key: "autoSplitTweets" },
				},
			],
		};
	}

	private schedulingGroup(): SettingDefinitionGroup {
		const whenEnabled = () => this.noteTweet.settings.scheduling.enabled;
		return {
			type: "group",
			heading: "Scheduling",
			items: [
				{
					name: "Enable scheduling",
					desc: "Post tweets on a schedule through a self-hosted scheduler. Requires setup.",
					control: { type: "toggle", key: "scheduling.enabled" },
				},
				{
					name: "Scheduler URL",
					desc: "The base URL of your scheduler endpoint.",
					visible: whenEnabled,
					control: {
						type: "text",
						key: "scheduling.url",
						placeholder: "https://scheduler.example.com",
					},
				},
				{
					name: "Scheduler password",
					desc: "Password configured on your scheduler.",
					visible: whenEnabled,
					render: (setting: Setting) =>
						this.renderSecretInput(
							setting,
							SECRET_IDS.schedulerPassword,
							"Scheduler password",
							() => this.noteTweet.refreshScheduler(),
						),
				},
				{
					name: "Scheduled tweets",
					desc: "View and manage tweets you have scheduled.",
					visible: whenEnabled,
					render: (setting: Setting) => {
						setting.addButton((button) =>
							button
								.setButtonText("Open")
								.onClick(() => this.openScheduledTweets()),
						);
					},
				},
			],
		};
	}

	private secretRow(
		name: string,
		id: SecretId,
		placeholder: string,
		desc?: string,
	): SettingDefinition {
		return {
			name,
			...(desc ? { desc } : {}),
			render: (setting: Setting) =>
				this.renderSecretInput(setting, id, placeholder, () =>
					this.scheduleReconnect(),
				),
		};
	}

	private renderSecretInput(
		setting: Setting,
		id: SecretId,
		placeholder: string,
		onChanged: () => void,
	): void {
		setting.addText((text) => {
			text.inputEl.type = "password";
			text
				.setPlaceholder(placeholder)
				.setValue(getSecret(this.app, id))
				.onChange((value) => {
					setSecret(this.app, id, value);
					onChanged();
				});
		});
	}

	private legacyData(): LegacyCredentialData {
		return this.noteTweet.settings as unknown as LegacyCredentialData;
	}

	private refreshStatus(message?: string): void {
		if (!this.statusEl) return;
		if (message) {
			this.statusEl.setText(message);
			this.statusEl.removeClass("nt-status--ok", "nt-status--err");
			return;
		}
		const { isConnected, lastError } = this.noteTweet.twitter;
		let text: string;
		if (isConnected) text = "Connected to X.";
		else if (lastError) text = `Not connected: ${lastError}`;
		else text = "Not connected. Enter your credentials.";
		this.statusEl.setText(text);
		this.statusEl.toggleClass("nt-status--ok", isConnected);
		this.statusEl.toggleClass("nt-status--err", !isConnected);
	}

	private scheduleReconnect(): void {
		if (this.reconnectTimer !== null) window.clearTimeout(this.reconnectTimer);
		this.refreshStatus("Verifying credentials...");
		this.reconnectTimer = window.setTimeout(() => {
			this.reconnectTimer = null;
			void this.noteTweet.reconnect()
				.catch(() => {})
				.then(() => this.refreshStatus());
		}, RECONNECT_DELAY_MS);
	}

	private openScheduledTweets(): void {
		this.noteTweet.refreshScheduler();
		if (!this.noteTweet.scheduler) {
			new Notice("Set a scheduler URL first.");
			return;
		}
		new ScheduledTweetsModal(this.app, this.noteTweet.scheduler).open();
	}

	private async migrate(): Promise<void> {
		const data = this.legacyData();
		const encrypted = legacyCredentialsEncrypted(data);

		let password: string | undefined;
		if (encrypted) {
			const entered = await InputPromptModal.prompt(
				this.app,
				"Enter your Secure Mode password",
				{ password: true },
			);
			if (!entered) return;
			password = entered;
		}

		let credentials;
		try {
			credentials = readLegacyCredentials(data, password);
		} catch {
			log.error("Could not decrypt your credentials - wrong password?");
			return;
		}

		if (encrypted) {
			const ok = await this.noteTweet.twitter.connect(credentials);
			if (!ok) {
				log.error(
					"Those credentials did not work. Check your password and try again.",
				);
				return;
			}
		}

		storeCredentials(this.app, credentials);
		stripLegacyCredentials(data);
		await this.noteTweet.saveSettings();
		// Re-run the connection test with the credentials we just migrated rather
		// than reading them back from SecretStorage: the read can race its async
		// write and leave the status stuck on "Not connected" right after a
		// successful migration.
		await this.noteTweet.twitter.connect(credentials);
		this.noteTweet.refreshScheduler(credentials.schedulerPassword);
		new Notice("NoteTweet: credentials moved to secure storage.");
		this.refreshStatus();
		this.update();
	}
}
