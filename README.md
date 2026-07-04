## NoteTweet for Obsidian
This plugin allows you to post to X (formerly Twitter) directly from Obsidian.

[![Release](https://img.shields.io/github/v/release/chhoumann/notetweet_obsidian?style=for-the-badge)]()
[![Github All Releases](https://img.shields.io/github/downloads/chhoumann/notetweet_obsidian/total.svg?style=for-the-badge&logo=appveyor)]()

### Features
- **Composer** (`Post tweet`) - a modal for writing single tweets or threads. It pre-fills from your current selection: a `THREAD START`/`THREAD END` block becomes a pre-split thread, and other text is auto-split for you.
- **Post selection as tweet** - posts the current editor selection as a single tweet, immediately.
- **Post file as thread** - parses the first `THREAD START`/`THREAD END` block in the active note and posts it as a thread.
- **Encrypted credentials** - your API keys are kept in Obsidian's built-in encrypted Secret Storage, not in the plugin's `data.json`.
- **Auto-split** - long text is split into a thread at 280 characters (toggle in settings). Disabling it allows longer tweets, which require a paid X plan.
- **Images** - include an image by adding a `[[wikilink]]` to an image file (gif, jpg, jpeg, png, webp, bmp) in the tweet text (desktop only).
- **Tweet tag** - optionally append a tag to your note after posting, so you can keep track of what you've tweeted.
- **Delete/undo** - after posting, a modal lets you delete the tweets you just posted.
- **Scheduling** (optional, advanced) - post on a schedule through a self-hosted scheduler. Follow [this guide](./GuideToSettingUpScheduler.md) to set it up.

Feel free to recommend features!

![8jE9wvKuls](https://user-images.githubusercontent.com/29108628/109525702-16c97180-7ab2-11eb-8bc0-3c4bc79a6b7a.gif)

## How to use
### Installation
This plugin has been added to the community plugin browser in Obsidian. You can get it from there.

If you want to watch a video on how to set up this plugin, click [here](https://www.youtube.com/watch?v=jx09b1Ien3Q).

#### Manual Installation
*Please note that these steps are not necessary anymore. You can get the plugin from the community plugin browser. Just install from there and jump to Setup.*

1. Go to [Releases](https://github.com/chhoumann/notetweet_obsidian/releases) and download the ZIP file from the latest release.
2. This ZIP file should be extracted in your Obsidian plugins folder. If you don't know where that is, you can go to `Community Plugins` inside Obsidian. There is a folder icon on the right of `Installed Plugins`. Click that and it opens your plugins folder.
3. Extract the contents of the ZIP file there.
4. Proceed to Setup

#### Setup
1. Go to [developer.x.com](https://developer.x.com) and sign up for a developer account if you haven't already.
2. Create a new App in the [Developer Portal](https://developer.x.com/en/portal/dashboard). New apps created at developer.x.com are automatically placed inside a Project, which is **required** for the X API v2. (A legacy, non-Project app causes a 403 `Client Forbidden` with reason `client-not-enrolled` - see Troubleshooting.)
3. On app creation you're shown the **API Key**, the **API Key Secret**, and a Bearer Token. Copy the API Key and API Key Secret - the portal names these differently than the plugin's fields:
   - **API Key** = your Consumer Key
   - **API Key Secret** (some UIs call it **Secret Key**) = your Consumer Secret
   - The **Access Token** and **Access Token Secret** are **not** shown here - you generate them in the next step.
4. Enable posting and generate the user tokens (this is the extra step people miss):
   - In the app's **Settings** tab, open **User authentication settings** and click **Edit**.
   - Enable **OAuth 1.0a**, set **App permissions** to **Read and write**, then **Save**.
   - Open the **Keys and tokens** tab, find **Access Token and Secret**, and click **Generate**. This gives you the **Access Token** and **Access Token Secret**.
   - If you change App permissions *after* generating the Access Token, regenerate the Access Token - otherwise it stays read-only.
5. Paste all four values - **API Key**, **API Key Secret**, **Access Token**, and **Access Token Secret** - into the plugin settings in Obsidian. They are stored in Obsidian's encrypted Secret Storage (see 'Credentials & security' below).

**Important Notes:**
- Credentials are shown only once in the developer portal - if you lose them, regenerate new ones.
- Ensure your App has **Read and write** permissions, not just Read, and regenerate the Access Token after changing permissions.
- Your App must be attached to a Project (required for X API v2). New apps are enrolled automatically; legacy apps must be attached manually.

You'll see a connection indicator that tells you whether you're connected and, when a connection fails, the exact reason X returned (for example the `client-not-enrolled` message).

### Credentials & security
Your API key, API secret, access token, and access token secret are kept in Obsidian's built-in encrypted Secret Storage (`app.secretStorage`), not in the plugin's `data.json`. Because Secret Storage is used, this plugin requires **Obsidian 1.13.0 or newer**.

**Migrating from an older version.** If you're upgrading from a version that stored credentials in `data.json`, the settings tab shows a **Migrate credentials** section at the top with a **Migrate now** button. Click it to move your existing credentials into Secret Storage. If you previously enabled the old password-based Secure Mode, the button first prompts for that password so it can decrypt your credentials before storing them - the migration is lossless. A one-time notice on load points you to settings, and once you've migrated, your credentials no longer live in `data.json`.

## Composer
Run the `Post tweet` command to open the composer, where you can craft threads or single tweets. If you have text selected, it is ported into the composer automatically: a `THREAD START`/`THREAD END` block opens as a pre-split thread, and any other text is auto-split into tweets when it exceeds 280 characters. You can also paste text in, and anything longer than 280 characters is split for you. The composer has a **Post** button, and a **Schedule** button when scheduling is enabled.

### Composer Shortcuts
- `Backspace` to delete an empty tweet
- `Enter` (at max length) or `Alt + Enter` to make a new tweet
- `Ctrl + Enter` to insert a tweet below
- `Shift + Enter` to insert a tweet above
- `Ctrl + ArrowUp` to focus the tweet above
- `Ctrl + ArrowDown` to focus the tweet below
- `Ctrl + Shift + ArrowUp` to move the current tweet up
- `Ctrl + Shift + ArrowDown` to move the current tweet down
- `Ctrl + Shift + Delete` to delete the focused tweet

## Quick posts
Single tweets are simple. Just select some text and run the `Post selection as tweet` command to post it immediately.

To post a thread straight from a note, run the `Post file as thread` command. It detects the first `THREAD START`/`THREAD END` block in the active note and posts it.

**Threads** have a specific format. Only the first thread block in a file is detected.

Format:
```
THREAD START

Here you can type the first tweet in your thread.

Spacing is fine.

---
Separation between tweets is done using a line containing only three dashes - just like you see above.

---
Enjoy!

THREAD END
```

Threads must start with `THREAD START` and end with `THREAD END`, and individual tweets are separated by a line containing only `---`.

## Scheduling Posts
Scheduling is optional and advanced. It posts through a self-hosted scheduler endpoint, and it requires the **Natural Language Dates** community plugin for entering times. Follow [this guide](./GuideToSettingUpScheduler.md) to set it up.

## Troubleshooting

### Not connected - 403 `Client Forbidden` (`client-not-enrolled`)
This is the most common setup failure. It means the app your credentials come from is **not attached to a Project**, so it isn't enrolled to use the X API v2 write endpoints. The plugin surfaces this exact reason in the connection status.

To fix it:
1. In the [Developer Portal](https://developer.x.com/en/portal/dashboard), either create a **fresh app** (new apps are automatically enrolled in a Project) or attach your existing app to a Project.
2. Regenerate your **Access Token and Secret** (Keys and tokens -> Access Token and Secret -> Generate), since the tokens are tied to the app.
3. Paste the updated credentials into the plugin settings and re-check the connection indicator.

### Authentication Error (401)
If you're seeing "TypeError: Cannot read properties of undefined (reading 'data')" or authentication errors even though the plugin shows as "connected":

1. **Verify your X app is attached to a Project**
   - Go to [developer.x.com](https://developer.x.com)
   - Navigate to your app settings
   - Ensure your app is attached to a Project (required for X API v2)

2. **Check your system clock**
   - Authentication can fail if your system time is incorrect
   - Ensure your computer's clock is synchronized

3. **Regenerate your access tokens**
   - In the X Developer Portal, regenerate your Access Token & Secret
   - Update the plugin settings with the new tokens

4. **Verify app permissions**
   - Your X app must have "Read and Write" permissions
   - If you recently changed permissions, regenerate your tokens

5. **Check for token expiration**
   - X API tokens can expire after extended periods of non-use
   - Simply regenerating them often resolves this issue

6. **Check your access tier and usage limits**
   - The free tier can post (write), so it works for most use cases. (Basic is a separate paid tier - you don't need it just to post.)
   - Check your usage limits in the developer portal if you're hitting rate limits

### Common Issues
- **Media upload failures**: Ensure your image files are in a supported format (gif, jpg, jpeg, png, webp, bmp) and accessible in your vault.
