import { writable } from "svelte/store";

export const tweetStore = writable<string[]>([]);
