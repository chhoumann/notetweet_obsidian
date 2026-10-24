import { defineConfig } from "vitest/config";
import * as path from "path";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    // datetime tests switch process.env.TZ, which only takes effect in forks.
    pool: "forks",
    include: ["src/**/*.test.ts", "tests/*.test.ts"],
    exclude: ["node_modules/**", "tests/e2e/**"],
    // Transform twitter-text so its `punycode` import resolves to the npm
    // package the production bundle ships, not Node's deprecated builtin.
    server: { deps: { inline: ["twitter-text"] } },
  },
  resolve: {
    alias: {
      obsidian: path.resolve("./tests/obsidian.ts"),
      punycode: "punycode/",
    },
  },
});
