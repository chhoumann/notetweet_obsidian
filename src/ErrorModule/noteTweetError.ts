import {ErrorLevel} from "./errorLevel";

export interface NoteTweetError {
    message: string,
    level: ErrorLevel,
    time: number
}