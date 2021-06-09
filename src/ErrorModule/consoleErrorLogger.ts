import {ErrorLevel} from "./errorLevel";
import {NoteTweetError} from "./noteTweetError";
import {NoteTweetLogger} from "./noteTweetLogger";

export class ConsoleErrorLogger extends NoteTweetLogger {
    public ErrorLog: NoteTweetError[] = [];

    public logError(errorMsg: string) {
        const error = this.getNoteTweetError(errorMsg, ErrorLevel.Error);
        this.addMessageToErrorLog(error);

        console.error(this.formatOutputString(error));
    }

    public logWarning(warningMsg: string) {
        const warning = this.getNoteTweetError(warningMsg, ErrorLevel.Warning);
        this.addMessageToErrorLog(warning);

        console.warn(this.formatOutputString(warning));
    }

    public logMessage(logMsg: string) {
        const log = this.getNoteTweetError(logMsg, ErrorLevel.Log);
        this.addMessageToErrorLog(log);

        console.log(this.formatOutputString(log));
    }

    private addMessageToErrorLog(error: NoteTweetError): void {
        this.ErrorLog.push(error);
    }
}