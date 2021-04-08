<script lang="ts">
    import { tweetStore } from "../Stores";

    let tweets: string[];

    tweetStore.subscribe(value => tweets = value);

    export let drafting: boolean;
    export let onAddTweet: (pos?: number) => void;
    export let onToggleDrafting: (value: boolean) => void;
    export let onSubmit: any;

</script>

<div class="postTweetModal">
    <div class="tweetTooltip">
        <span class="tweetTooltipBody">
            Please read the documentation on the Github repository.
            Click <a target="_blank" href="https://github.com/chhoumann/notetweet_obsidian">here</a> to go there.
            There are lots of shortcuts and features to explore 😁
        </span>
    </div>

    <!-- TweetZone -->
    <div>
        {#if tweets && tweets.length > 0}
            {#each tweets as tweet}
                <label>
                    <textarea bind:value={tweet} on:input={() => tweetStore.set(tweets)} class="tweetArea"></textarea>
                    {tweet.length} / 280 characters
                </label>
            {/each}
        {/if}
    </div>

    <button on:click={onAddTweet(null)}>+</button>
    <button on:click={onSubmit}>Post!</button>

    <label>
        <input type="checkbox" bind:checked={drafting} on:click={() => onToggleDrafting(drafting)}>
        Drafting
    </label>

</div>