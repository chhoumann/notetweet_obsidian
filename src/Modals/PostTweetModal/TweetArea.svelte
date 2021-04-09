<label
  class="ntLengthChecker"
  style="color: {getLengthCheckerColor(tweet)}"
>
    <textarea
      bind:value={tweet}
      bind:this={el}
      on:input={onTweetInput}
      on:keypress
      class="tweetArea"
    ></textarea>
  {tweet.length} / 280 characters
</label>


<script lang="ts">
  import { createEventDispatcher } from "svelte";

  const MAX_TWEET_LENGTH: number = 280;
  let el: HTMLTextAreaElement;

  export let tweet: string;
  export const focusMe: () => void = () => (el.focus());
  const dispatch = createEventDispatcher();

  function onTweetInput() {
    // Auto resize to fit tweet size.
    el.style.height = "auto";
    el.style.height = el.scrollHeight + "px";

    dispatch("tweetInput");

    //tweetStore.set(tweets);
  }

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
</script>