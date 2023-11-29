<script lang="ts">
    export let posts: any[];
    export let onDelete: any;
    export let onAccept: any;
    let multiplePosts = posts.length > 1;
</script>

<div>
    {#if multiplePosts}
        <h2>Your tweets are live! Check them out here: </h2>
    {:else}
        <h2>Your tweet is live! Check it out here: </h2>
    {/if}

    {#each posts as post}
        <a href="https://twitter.com/twitter/status/{post.data.id}">{post.data.text}</a>
        <br>
    {/each}

    <button
        on:click={onAccept()}
        class="greenSuccessButton"
        style="float: right; margin-top: 1rem;"
    >
        Great!
    </button>

    <button
        on:click={onDelete()}
        class="redWarningButton"
        style="float: right; margin: 1rem;"
    >
        Delete
    </button>

</div>