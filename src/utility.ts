import GenericInputPrompt from "./Modals/GenericInputPrompt";
import {App} from "obsidian";

export async function promptForDateTime(app: App): Promise<number> {
    const input: string = await GenericInputPrompt.Prompt(app, "Update scheduled time");
    // @ts-ignore
    const nld = app.plugins.plugins["nldates-obsidian"].parser.chrono.parseDate(input);
    const nldparsed = Date.parse(nld);
    return new Date(nldparsed).getTime();
}