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
	accountSecretId,
	clearAccountCredentials,
	getSecret,
	hasSecretStorage,
	setSecret,
	type TwitterCredentials,
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
import { createAccount, type XAccount } from "./settings";

const RECONNECT_DELAY_MS = 800;

/**
 * Declarative settings tab (Obsidian 1.13 API). Non-secret settings are plain
 * `control` definitions round-tripped through {@link getControlValue} /
 * {@link setControlValue}; credentials use masked `render` rows backed by
 * SecretStorage; a migration group appears only while legacy credentials linger
 * in the plugin's data file.
 */
export class NoteTweetSettingsTab extends PluginSettingTab {
	private readonly statusEls = new Map<string, HTMLElement>();
	private reconnectTimer: number | null = null;

	constructor(app: App, private readonly noteTweet: NoteTweet) {
		super(app, noteTweet);
	}

	override getControlValue(key: string): unknown {
		const settings = this.noteTweet.settings;
		switch (key) {
			case "defaultAccountId":
				return settings.defaultAccountId;
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
			case "defaultAccountId":
				settings.defaultAccountId = String(value);
				break;
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
			this.accountsGroup(),
			...this.noteTweet.settings.accounts.map((account) =>
				this.accountCredentialsGroup(account),
			),
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

	private accountsGroup(): SettingDefinitionGroup {
		return {
			type: "group",
			heading: "X accounts",
			items: [
				{
					name: "Secret storage unavailable",
					desc: "This version of Obsidian does not support secret storage, so credentials cannot be stored securely. Update Obsidian to use NoteTweet.",
					visible: () => !hasSecretStorage(this.app),
				},
				{
					name: "Default account",
					desc: "Used by Post selection as tweet and Post file as thread. The composer lets you choose per post.",
					visible: () => this.noteTweet.settings.accounts.length > 0,
					control: {
						type: "dropdown",
						key: "defaultAccountId",
						options: Object.fromEntries(
							this.noteTweet.settings.accounts.map(({ id, name }) => [id, name]),
						),
					},
				},
				{
					name: "Add account",
					desc: "Create a named X account. Its four credentials are stored only in Obsidian Secret Storage.",
					render: (setting: Setting) => {
						setting.addButton((button) =>
							button
								.setButtonText("Add account")
								.setCta()
								.onClick(() => this.addAccount()),
						);
					},
				},
			],
		};
	}

	private accountCredentialsGroup(account: XAccount): SettingDefinitionGroup {
		return {
			type: "group",
			heading: account.name,
			items: [
				{
					name: "Account name",
					render: (setting: Setting) => {
						setting.addText((text) =>
							text.setValue(account.name).onChange(async (value) => {
								const name = value.trim();
								if (!name) return;
								account.name = name;
								await this.noteTweet.saveSettings();
							}),
						);
					},
				},
				{
					name: "Connection",
					searchable: false,
					render: (setting: Setting) => {
						const status = setting.controlEl.createSpan();
						this.statusEls.set(account.id, status);
						this.refreshStatus(account.id);
						setting.addButton((button) =>
							button
								.setButtonText("Test")
								.onClick(() => this.testConnection(account.id)),
						);
					},
				},
				this.accountSecretRow(
					account.id,
					"API key",
					"apiKey",
					"Enter your API key",
					"Your app's API Key (also called the Consumer Key), from Keys and tokens in the X developer portal.",
				),
				this.accountSecretRow(
					account.id,
					"API secret",
					"apiSecret",
					"Enter your API secret",
					"Your app's API Key Secret (the Consumer Secret).",
				),
				this.accountSecretRow(
					account.id,
					"Access token",
					"accessToken",
					"Enter your access token",
					"Generate under Keys and tokens -> Access Token and Secret (requires Read and Write user authentication).",
				),
				this.accountSecretRow(
					account.id,
					"Access token secret",
					"accessTokenSecret",
					"Enter your access token secret",
					"The Access Token Secret shown when you generate the access token.",
				),
				{
					name: "Remove account",
					desc: "Remove this account and clear its credentials from Secret Storage.",
					render: (setting: Setting) => {
						setting.addButton((button) =>
							button
								.setButtonText("Remove")
								.setDestructive()
								.onClick(() => this.removeAccount(account)),
						);
					},
				},
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

	private accountSecretRow(
		accountId: string,
		name: string,
		field: keyof TwitterCredentials,
		placeholder: string,
		desc?: string,
	): SettingDefinition {
		return {
			name,
			...(desc ? { desc } : {}),
			render: (setting: Setting) =>
				this.renderSecretInput(
					setting,
					accountSecretId(accountId, field),
					placeholder,
					() => this.scheduleReconnect(accountId),
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

	private refreshStatus(
		accountId: string,
		message = "Not checked.",
		connected?: boolean,
	): void {
		const statusEl = this.statusEls.get(accountId);
		if (!statusEl) return;
		statusEl.setText(message);
		statusEl.toggleClass("nt-status--ok", connected === true);
		statusEl.toggleClass("nt-status--err", connected === false);
	}

	private async testConnection(accountId: string): Promise<void> {
		this.refreshStatus(accountId, "Verifying credentials...");
		const client = await this.noteTweet.connectAccount(accountId);
		if (client.isConnected) {
			this.refreshStatus(accountId, "Connected to X.", true);
			return;
		}
		const message = client.lastError
			? `Not connected: ${client.lastError}`
			: "Not connected. Enter all four credentials.";
		this.refreshStatus(accountId, message, false);
	}

	private scheduleReconnect(accountId: string): void {
		if (this.reconnectTimer !== null) window.clearTimeout(this.reconnectTimer);
		this.refreshStatus(accountId, "Waiting to verify...");
		this.reconnectTimer = window.setTimeout(() => {
			this.reconnectTimer = null;
			void this.testConnection(accountId);
		}, RECONNECT_DELAY_MS);
	}

	private async addAccount(): Promise<void> {
		const settings = this.noteTweet.settings;
		const used = new Set(settings.accounts.map(({ name }) => name));
		let number = settings.accounts.length + 1;
		while (used.has(`Account ${number}`)) number += 1;
		const account = createAccount(`Account ${number}`);
		settings.accounts.push(account);
		if (!settings.defaultAccountId) settings.defaultAccountId = account.id;
		await this.noteTweet.saveSettings();
		this.update();
	}

	private async removeAccount(account: XAccount): Promise<void> {
		if (!window.confirm(`Remove the X account "${account.name}"?`)) return;

		const settings = this.noteTweet.settings;
		const previousAccounts = settings.accounts;
		const previousDefault = settings.defaultAccountId;
		settings.accounts = settings.accounts.filter(({ id }) => id !== account.id);
		if (settings.defaultAccountId === account.id) {
			settings.defaultAccountId = settings.accounts[0]?.id ?? "";
		}
		try {
			await this.noteTweet.saveSettings();
		} catch (error) {
			settings.accounts = previousAccounts;
			settings.defaultAccountId = previousDefault;
			throw error;
		}
		clearAccountCredentials(this.app, account.id);
		this.statusEls.delete(account.id);
		this.update();
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
			const ok = await this.noteTweet.verifyCredentials(credentials);
			if (!ok) {
				log.error(
					"Those credentials did not work. Check your password and try again.",
				);
				return;
			}
		}

		const settings = this.noteTweet.settings;
		const account = createAccount(
			settings.accounts.length === 0 ? "Default" : "Imported account",
		);
		settings.accounts.push(account);
		if (!settings.defaultAccountId) settings.defaultAccountId = account.id;
		storeCredentials(this.app, account.id, credentials);
		stripLegacyCredentials(data);
		await this.noteTweet.saveSettings();
		this.noteTweet.refreshScheduler(credentials.schedulerPassword);
		new Notice(`NoteTweet: credentials moved to the ${account.name} account.`);
		this.update();
	}
}
