<div class="postTweetModal">
    <PostTweetHelpTooltip />

    <!-- TweetZone -->
    <div>
        {#each tweets as tweet, i}
            <TweetArea
                on:keypress={e => shortcutHandler(e, i)}
                bind:this={tweetBoxes[i]}
                bind:tweet={tweet}
            />
        {/each}
    </div>

    <button on:click={() => addEmptyTweet()}>+</button>
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
    import { onMount, tick } from "svelte";
    import PostTweetHelpTooltip from "./PostTweetHelpTooltip.svelte";
    import { Notice } from "obsidian";
    import TweetArea from "./TweetArea.svelte";

    export let drafting: boolean;
    export let onToggleDrafting: (value: boolean) => void;
    export let onSubmit: any;

    let tweets: string[] = [];
    let tweetBoxes: TweetArea[] = [];
    tweetStore.subscribe(value => tweets = value);

    onMount(() => {
        if ((tweets.length <= 1 && tweets[0]) || tweets.length == 0)
            addEmptyTweet();

        tick().then(() => tweetBoxes[tweetBoxes.length - 1].focusMe())
    });

    function addEmptyTweet(pos?: number) {
        if (tweets.indexOf("") !== -1) {
            new Notice(
              "You cannot add a new tweet when there are empty tweets."
            );
            return false;
        }

        if (pos == null) tweets.push("");
        else tweets.splice(pos, 0, "");

        tweetStore.set(tweets);

        return false;
        // textarea.addEventListener(
        //   "paste",
        //   this.onPasteMaxLengthHandler(textarea, textZone)
        // );
    }

    function deleteTweet(position: number) {
        tweets.splice(position, 1);

        tweetStore.set(tweets);
    }

    async function shortcutHandler(key: KeyboardEvent, i: number) {
        if (key.code == "Enter" && key.ctrlKey) {
            if (addEmptyTweet(i + 1)) {
                while (tweetBoxes[i + 1] == null)
                    await tick();

                tweetBoxes[i+1].focusMe();
            }
            key.preventDefault();
        }

        if (key.code == "Enter" && key.shiftKey) {
            if (addEmptyTweet(i)) {
                while (tweetBoxes[i] == null)
                    await tick();

                tweetBoxes[i].focusMe();
            }
            key.preventDefault();
        }
    }

</script>