<script lang="ts">
  import { onMount } from "svelte";

  export let tweet: string;
  let el: HTMLTextAreaElement;

  onMount(() => {
    el.focus();
  })
</script>

<textarea
  bind:value={tweet}
  bind:this={el}
  on:input
  on:keyup
  class="tweetArea"
></textarea>