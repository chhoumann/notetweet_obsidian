import GenericInputPrompt from "./Modals/GenericInputPrompt";

export async function promptForDateTime(): Promise<number> {
    const input: string = await GenericInputPrompt.Prompt(this.app, "Update scheduled time");
    // @ts-ignore
    const nld = this.app.plugins.plugins["nldates-obsidian"].parser.chrono.parseDate(input);
    const nldparsed = Date.parse(nld);
    return new Date(nldparsed).getTime();
}