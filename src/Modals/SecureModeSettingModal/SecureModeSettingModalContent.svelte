<script lang="ts">
    export let enable: boolean;
    export let onSubmit: any;
    let passwordInput: string;
</script>

<div>
    <h1>Secure Mode Settings</h1>
    <p>Please enter your password below and then click the button below.</p>
    <div class="tweetTooltip" style="float: right">
        Help
        <span class="tweetTooltipBody">
            Secure Mode enables you to encrypt your API keys with a password.
            The password will be required to use the plugin while Secure Mode is enabled.<br>
            Your API keys will remain stored, but will be overwritten with the encrypted keys.
            This means they will be unintelligible to anyone who doesn't know your password.<br>
            <strong>Please do note that this plugin cannot check if your passwords decrypts your keys correctly!
            This means you might have to re-enter your keys if the wrong password is entered.</strong>
        </span>
    </div>

    <label>
        <input bind:value={passwordInput} type="password">
    </label>

    <button on:click={() => onSubmit(passwordInput)} style="margin-left: 1rem;">
        {enable ? "Encrypt!" : "Decrypt!"}
    </button>
</div>