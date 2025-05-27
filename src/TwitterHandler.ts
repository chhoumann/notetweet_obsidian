import { SendTweetV2Params, TweetV2, TwitterApi } from "twitter-api-v2";
import { getMimeType } from "twitter-api-v2/dist/esm/v1/media-helpers.v1";
import NoteTweet from "./main";
import { log } from "./ErrorModule/logManager";

export class TwitterHandler {
  private twitterClient: TwitterApi;
  public isConnectedToTwitter = false;

  constructor(private plugin: NoteTweet) {}

  public connectToTwitter(
    apiKey: string,
    apiSecret: string,
    accessToken: string,
    accessTokenSecret: string
  ) {
    try {
      this.twitterClient = new TwitterApi({
        appKey: apiKey,
        appSecret: apiSecret,
        accessToken: accessToken,
        accessSecret: accessTokenSecret,
      });
      this.isConnectedToTwitter = true;
    } catch (e) {
      this.isConnectedToTwitter = false;
    }
  }

  public async postThread(threadContent: string[]) {
    let tweets = [];

    for (const threadTweet of threadContent) {
      const tweet: SendTweetV2Params = await this.constructTweet(threadTweet);
      tweets.push(tweet);
    }
    try {
      return await this.twitterClient.v2.tweetThread(tweets);
    } catch (e) {
      console.log(`error in posting tweet thread: ${e}`);
      throw e;
    }
  }

  IMAGE_REGEX: RegExp = new RegExp(
    /!?\[\[([a-zA-Z 0-9-\.]*\.(gif|jpe?g|tiff?|png|webp|bmp))\]\]/
  );
  public async postTweet(tweetText: string) {
    const tweet: SendTweetV2Params = await this.constructTweet(tweetText);

    try {
      return await this.twitterClient.v2.tweet(tweet);
    } catch (e) {
      console.log(`error in posting tweet. ${e}`);
      throw e;
    }
  }

  private async constructTweet(tweet: string): Promise<SendTweetV2Params> {
    let media_ids: string[] = [];
    let processedTweet = tweet;

    while (this.IMAGE_REGEX.test(processedTweet)) {
      const match = this.IMAGE_REGEX.exec(processedTweet);
      const fileName: string = match[1];

      // TODO: correctly handle the source path
      const file = this.plugin.app.metadataCache.getFirstLinkpathDest(fileName, "");
      const mimeType = getMimeType(fileName);
      const data = Buffer.from(await file.vault.readBinary(file));
      const media_id = await this.twitterClient.v1.uploadMedia(data, { mimeType });

      if (media_id) {
        media_ids.push(media_id);
        processedTweet = processedTweet.replace(this.IMAGE_REGEX, "");
      } else {
        log.logWarning(
          `image '${fileName}' found but could not upload it to Twitter. Data is null/undefined: ${!!media_ids}.`
        );
      }
    }

    return {
      text: processedTweet,
      ...(media_ids.length > 0 ? { media: { media_ids } } : {}),
    };
  }

  public async deleteTweets(tweets: TweetV2[]) {
    try {
      for (const tweet of tweets)
        await this.twitterClient.v2.deleteTweet(tweet.id);

      return true;
    } catch (e) {
      log.logError(`error in deleting tweets. ${e}`);
      return false;
    }
  }
}
