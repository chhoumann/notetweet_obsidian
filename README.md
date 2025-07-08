## NoteTweet🐦 for Obsidian
This plugin allows you to post to X (formerly Twitter) directly from Obsidian.

[![Release](https://img.shields.io/github/v/release/chhoumann/notetweet_obsidian?style=for-the-badge)]()
[![Github All Releases](https://img.shields.io/github/downloads/chhoumann/notetweet_obsidian/total.svg?style=for-the-badge&logo=appveyor)]()

### Features
- Post to X (tweets) of selected text
- Post threads from file
- Automatically appends a tag to your post (to keep track of what you've posted)
- **Secure mode** - encrypts your API keys such that they can only be accessed with a password.
- Delete post/thread that was just posted (undo)
- Post Mode - a modal dedicated to writing posts and threads.
- Images are supported - just include a `[[link]]` to your images!
- Scheduling posts - follow [this guide](./GuideToSettingUpScheduler.md) to set it up.


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
2. Navigate to the [Developer Portal](https://developer.x.com/en/portal/products/free) and create a new Project.
3. Within your Project, create a new App. Make sure to enable **Read and Write** permissions (required for posting).
4. In your App settings, navigate to the "Keys and tokens" section.
5. Generate and save the following credentials:
   - **API Key and API Key Secret** (used for OAuth 1.0a authentication)
   - **Access Token and Access Token Secret** (represents your account for posting)
6. Paste these four values into the plugin settings in Obsidian.

**Important Notes:**
- Store your credentials securely - they only display once in the developer portal
- If you lose them, you'll need to regenerate new ones
- Ensure your App has "Read and Write" permissions, not just "Read"
- Your App must be attached to a Project (this is now required for X API v2)

You'll see an indicator which tells you if you're connected or not.

## Post Mode
Using the `Post Tweet` command, a new modal will open. There, you can craft threads - or single posts.
You can select both text or threads before using the command and it'll automatically port it into the modal. If the selected text is longer than 280 characters, it'll break it into a thread for you.
You can paste text into the modal. If that text is longer than 280 characters, it'll also break it into multiple posts.

### Post Mode Shortcuts
- `Backspace` to delete empty post
- `Enter` to make new post if max length
- `Alt + Enter` to make new post
- `Ctrl + Enter` to insert a post below
- `Shift + Enter` to insert a new post above
- `Ctrl + ArrowUp` to focus post above
- `Ctrl + ArrowDown` to focus post below
- `Ctrl + Shift + ArrowUp` to move post up
- `Ctrl + Shift + ArrowDown` to move post down
- `Ctrl + Shift + Delete` to delete the post you have focused

## Quick-posts
Single posts are simple. Just select some text and use the `Post Selected as Tweet` command.

**Threads** have a specific format. First off, it only detects the first thread in any file.

Format:
```
THREAD START

Here you can type the first post in your thread.

Spacing is fine.

---
Separation between posts is done using a newline and three dashes - just like you see above.

---
Enjoy!

THREAD END
```

Threads must start with `THREAD START` and end with `THREAD END`.


## Scheduling Posts
Follow [this guide](./GuideToSettingUpScheduler.md).

## Troubleshooting

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

6. **Verify Basic access is sufficient**
   - The free Basic tier should work for most use cases
   - Check your usage limits in the developer portal if you're hitting rate limits

### Common Issues
- **Media upload failures**: Ensure your image files are in a supported format (gif, jpg, jpeg, png, webp, bmp) and accessible in your vault.
