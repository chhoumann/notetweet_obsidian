export interface Deferred<T> {
	promise: Promise<T>;
	resolve: (value: T | PromiseLike<T>) => void;
}

/** ES2020-compatible equivalent of the resolve side of Promise.withResolvers. */
export function deferred<T>(): Deferred<T> {
	let resolve!: Deferred<T>["resolve"];
	const promise = new Promise<T>((resolvePromise) => {
		resolve = resolvePromise;
	});
	return { promise, resolve };
}
