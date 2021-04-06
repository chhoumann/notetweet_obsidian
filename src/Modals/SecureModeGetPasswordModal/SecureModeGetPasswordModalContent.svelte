<script lang="ts">
    let passwordInput: string;

    export let onSubmit: any;
</script>

<div>
    <h2>Secure Mode</h2>
    <p>Please enter your password to continue.</p>
    <label>
        Password
        <input bind:value={passwordInput} type="password">
    </label>
    <button on:click={onSubmit} style="margin-left: 1rem;">
        Submit
    </button>
</div>