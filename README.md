## NoteTweet🐦 for Obsidian
This plugin allows you to post tweets directly from Obsidian.

### Features
- Post tweets of selected text
- Post threads from file
- Automatically appends a tag to your tweet (to keep track of what you've posted)

### Coming...
- Ability to break text over 250 characters into multiple tweets instead of immediately posting
- Confirmation prompts
- Delete tweet/thread that was just posted (undo)
- Easier authentication (if possible?)

Feel free to recommend features!

![8jE9wvKuls](https://user-images.githubusercontent.com/29108628/109525702-16c97180-7ab2-11eb-8bc0-3c4bc79a6b7a.gif)

## How to use
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
