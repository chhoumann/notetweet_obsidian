## NoteTweet🐦 for Obsidian
This plugin allows you to post tweets directly from Obsidian.

[![Release](https://img.shields.io/github/v/release/chhoumann/notetweet_obsidian?style=for-the-badge)]()
[![Github All Releases](https://img.shields.io/github/downloads/chhoumann/notetweet_obsidian/total.svg?style=for-the-badge&logo=appveyor)]()

### Features
- Post tweets of selected text
- Post threads from file
- Automatically appends a tag to your tweet (to keep track of what you've posted)
- **Secure mode** - encrypts your API keys such that they can only be accessed with a password.

### Coming...
- Ability to break text over 250 characters into multiple tweets instead of simply rejecting
- Confirmation prompts
- Delete tweet/thread that was just posted (undo)
- Easier authentication (if possible?)


Feel free to recommend features!

![8jE9wvKuls](https://user-images.githubusercontent.com/29108628/109525702-16c97180-7ab2-11eb-8bc0-3c4bc79a6b7a.gif)

## How to use
### Installation
This plugin has been added to the community plugin browser in Obsidian. You can get it from there.

### Manual Installation

1. Go to [Releases](https://github.com/chhoumann/notetweet_obsidian/releases) and download the ZIP file from the latest release.
2. This ZIP file should be extracted in your Obsidian plugins folder. If you don't know where that is, you can go to `Community Plugins` inside Obsidian. There is a folder icon on the right of `Installed Plugins`. Click that and it opens your plugins folder.
3. Extract the contents of the ZIP file there.
4. Proceed to Setup

### Setup
1. Go to https://apps.twitter.com/app/new and create a new app. Make sure it is Read + Write (otherwise you can't tweet).
2. Get your API key & secret and access token & secret.
3. Paste those into the plugin settings.

You'll see an indicator which tells you if you're connected or not.

### Tweeting
Single tweets are simple. Just select some text and use the `Post Selected as Tweet` command.

**Threads** have a specific format. First off, it only detects the first thread in any file.

Format:
```
THREAD START

Here you can type the first tweet in your thread.

Spacing is fine.

---
Separation between tweets is done using a newline and three dashes - just like you see above.

---
Enjoy!

THREAD END
```

Threads must start with `THREAD START` and end with `THREAD END`.
