import { StatusesUpdate, TwitterClient } from "twitter-api-client";
import NoteTweet from "./main";
import {log} from "./ErrorModule/logManager";

export class TwitterHandler {
  private twitterClient: TwitterClient;
  public isConnectedToTwitter = false;

  constructor(private plugin: NoteTweet) {
  }

  public connectToTwitter(
    apiKey: string,
    apiSecret: string,
    accessToken: string,
    accessTokenSecret: string
  ) {
    try {
      this.twitterClient = new TwitterClient({
        apiKey,
        apiSecret,
        accessToken,
        accessTokenSecret,
      });
      this.isConnectedToTwitter = true;
    } catch (e) {
      this.isConnectedToTwitter = false;
    }
  }

  public async postThread(threadContent: string[]) {
    let postedTweets: StatusesUpdate[] = [];
    let previousPost: StatusesUpdate;

    for (const threadTweet of threadContent) {
      let isFirstTweet = threadContent.indexOf(threadTweet) == 0;
      const {tweet, media_ids} = await this.getImagesInTweet(threadTweet);

      previousPost = await this.twitterClient.tweets.statusesUpdate({
        status: tweet.trim(),
        media_ids,
        ...(!isFirstTweet && { in_reply_to_status_id: previousPost.id_str }),
      });

      postedTweets.push(previousPost);
    }

    return postedTweets;
  }

  IMAGE_REGEX: RegExp = new RegExp(/!?\[\[([a-zA-Z 0-9-\.]*\.(gif|jpe?g|tiff?|png|webp|bmp))\]\]/);
  public async postTweet(tweet: string) {
    const {tweet: processedTweet, media_ids} = await this.getImagesInTweet(tweet);

    return await this.twitterClient.tweets.statusesUpdate({
      status: processedTweet.trim(),
      media_ids
    });
  }

  private async getImagesInTweet(tweet: string): Promise<{ tweet: string, media_ids: string }> {
    let media_ids: string[] = [];
    let processedTweet = tweet;

    while (this.IMAGE_REGEX.test(processedTweet)) {
      const match = this.IMAGE_REGEX.exec(processedTweet);
      const fileName: string = match[1];

      // Link in [[...]] might not be the actual path because of the attachment folder.
      const file = this.plugin.app.vault.getFiles().find(f => f.name === fileName);
      const fullPath = (await this.plugin.app.vault.readBinary(file));

      const media_data = Buffer.from(fullPath).toString('base64');

      const media_id = (await this.twitterClient.media.mediaUpload({media_data, media_category: "tweet_image"}));

      if (media_id) {
        media_ids.push(media_id.media_id_string);
        processedTweet = processedTweet.replace(this.IMAGE_REGEX, "");
      } else {
        log.logWarning(`image '${fileName}' found but could not upload it to Twitter. Data is null/undefined: ${!!media_data}.`);
      }
    }

    return {tweet: processedTweet, media_ids: media_ids.join(",")}
  }

  public async deleteTweets(tweets: StatusesUpdate[]) {
    try {
      for (const tweet of tweets)
        await this.twitterClient.tweets.statusesDestroyById({
          id: tweet.id_str,
        });

      return true;
    } catch(e) {
      log.logError(`error in deleting tweets. ${e}`);
      return false;
    }
  }
}
