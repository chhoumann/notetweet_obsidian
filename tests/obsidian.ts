// Vitest runtime alias for `import ... from "obsidian"`. NoteTweet's unit suite
// runs in the `node` environment and cannot load the real Obsidian module, so
// this re-exports the shared, node-safe stub from obsidian-test-kit. The stub is
// import-safe in node (no DOM required), which is why no jsdom setup is wired up
// here. If a test needs an Obsidian API the kit does not cover yet, add it to
// obsidian-test-kit rather than forking a local stub.
export * from "obsidian-test-kit/stub";
export { default } from "obsidian-test-kit/stub";
