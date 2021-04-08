<div class="postTweetModal">
    <PostTweetHelpTooltip />

    <!-- TweetZone -->
    <div>
        {#if tweets && tweets.length > 0}
            {#each tweets as tweet}
                <label
                  class="ntLengthChecker"
                  style="color: {getLengthCheckerColor(tweet)}"
                >
                    <!--<TweetArea
                        bind:tweet={tweet}
                        on:input={e => onTweetInput(e.target)}
                        on:keyup={key => onTweetShortcut(key, key.target)}
                    />-->
                    <textarea
                      bind:value={tweet}
                      on:input={(e) => onTweetInput(e.target)}
                      on:keyup={(key) => onTweetShortcut(key, key.target)}
                      class="tweetArea"
                      ></textarea>
                    {tweet.length} / 280 characters
                </label>
            {/each}
        {/if}
    </div>

    <button on:click={() => onAddTweet()}>+</button>
    <button on:click={onSubmit}>Post!</button>

    <label>
        <input
          type="checkbox"
          bind:checked={drafting}
          on:click={() => onToggleDrafting(!drafting)}>
        Save draft
    </label>

</div>

<script lang="ts">
    import { tweetStore } from "../Stores";
    import { createEventDispatcher } from "svelte";
    import TweetArea from "./TweetArea.svelte";
    import PostTweetHelpTooltip from "./PostTweetHelpTooltip.svelte";

    export let drafting: boolean;
    export let onAddTweet: (pos?: number) => void;
    export let onToggleDrafting: (value: boolean) => void;
    export let onTweetShortcut: (key: any, textArea: any) => void;
    export let onSubmit: any;

    const MAX_TWEET_LENGTH: number = 280;
    const dispatch = createEventDispatcher();

    let tweets: string[];

    tweetStore.subscribe(value => tweets = value);

    function getLengthCheckerColor(tweet: string): string {
        const DEFAULT_COLOR = "#339900";
        const WARN1: number = MAX_TWEET_LENGTH - 50;
        const WARN2: number = MAX_TWEET_LENGTH - 25;
        const tweetLength = tweet.length;

        if (tweetLength >= MAX_TWEET_LENGTH) return "#cc3300";
        if (tweetLength > WARN2) return "#ff9966";
        if (tweetLength > WARN1) return "#ffcc00";
        if (tweetLength <= WARN1) return DEFAULT_COLOR;
    }

    function onTweetInput(element: any) {
        // Auto resize to fit tweet size.
        element.style.height = "auto";
        element.style.height = element.scrollHeight + "px";

        dispatch("tweetInput");

        tweetStore.set(tweets);
    }

</script>