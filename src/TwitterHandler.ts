import {StatusesUpdate, TwitterClient} from "twitter-api-client";

export class TwitterHandler {
    private twitterClient: TwitterClient;
    public isConnectedToTwitter = false;

    public connectToTwitter(apiKey: string, apiSecret: string, accessToken: string, accessTokenSecret: string) {
        try {
            this.twitterClient = new TwitterClient({
                apiKey, apiSecret, accessToken, accessTokenSecret
            });
            this.isConnectedToTwitter = true;
        }
        catch (e) {
            this.isConnectedToTwitter = false;
        }
    }

    public async postThread(threadContent: string[]) {
        let postedTweets: StatusesUpdate[] = [];
        let previousPost: StatusesUpdate;

        for (const tweet of threadContent) {
            let isFirstTweet = threadContent.indexOf(tweet) == 0;

            previousPost = await this.twitterClient.tweets.statusesUpdate({
                status: tweet.trim(),
                ...(!isFirstTweet && { in_reply_to_status_id: previousPost.id_str })
            })

            postedTweets.push(previousPost);
        }

        return postedTweets;
    }

    public async postTweet(tweet: string) {
        return await this.twitterClient.tweets.statusesUpdate({
            status: tweet.trim(),
        });
    }

    public async deleteTweets(tweets: StatusesUpdate[]) {
        try {
            for (const tweet of tweets)
                await this.twitterClient.tweets.statusesDestroyById({id: tweet.id_str});

            return true;
        }
        catch {
            return false;
        }
    }
}