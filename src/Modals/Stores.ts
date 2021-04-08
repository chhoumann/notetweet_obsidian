import { writable } from "svelte/store";

export const tweetStore = writable<string[]>([]);
export const tweetZoneStore = writable<HTMLDivElement>(null);
