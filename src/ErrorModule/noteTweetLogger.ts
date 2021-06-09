import {ILogger} from "./ILogger";
import {NoteTweetError} from "./noteTweetError";
import {ErrorLevel} from "./errorLevel";

export abstract class NoteTweetLogger implements ILogger {
    abstract logError(msg: string): void;

    abstract logMessage(msg: string): void;

    abstract logWarning(msg: string): void;

    protected formatOutputString(error: NoteTweetError): string {
        return `NoteTweet: (${error.level}) ${error.message}`;
    }

    protected getNoteTweetError(message: string, level: ErrorLevel): NoteTweetError {
        return {message, level, time: Date.now()};
    }
}