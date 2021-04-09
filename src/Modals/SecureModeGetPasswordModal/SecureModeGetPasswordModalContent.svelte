<script lang="ts">
    let passwordInput: HTMLInputElement;

    export let onSubmit: any;
</script>

<div>
    <h2>Secure Mode</h2>
    <p>Please enter your password to continue.</p>
    <label>
        <input bind:this={passwordInput} type="password">
    </label>
    <button on:click={() => onSubmit(passwordInput.value)} style="margin-left: 1rem;">
        Submit
    </button>
</div>