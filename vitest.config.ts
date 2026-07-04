import { defineConfig } from "vitest/config";
import * as path from "path";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.ts", "scripts/**/*.test.ts"],
    exclude: ["node_modules/**", "tests/e2e/**"],
  },
  resolve: {
    alias: {
      obsidian: path.resolve("./tests/obsidian-stub.ts"),
    },
  },
});
