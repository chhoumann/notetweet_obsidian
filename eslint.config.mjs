import globals from "globals";
import obsidianmd from "eslint-plugin-obsidianmd";
import tseslint from "typescript-eslint";

const sharedGlobals = {
  ...globals.node,
  ...globals.browser,
  activeDocument: "readonly",
  activeWindow: "readonly",
};

const obsidianGuidelineRules = {
  "obsidianmd/no-static-styles-assignment": "error",
  "obsidianmd/prefer-window-timers": "error",
  "obsidianmd/prefer-active-doc": "error",
  "obsidianmd/detach-leaves": "error",
  "obsidianmd/no-global-this": "error",
  "obsidianmd/settings-tab/no-manual-html-headings": "error",
  "obsidianmd/commands/no-plugin-name-in-command-name": "error",
};

export default tseslint.config(
  {
    ignores: [
      "node_modules/**",
      "main.js",
      "**/*.js.map",
      "coverage/**",
      "esbuild.config.mjs",
      "version-bump.mjs",
      ".obsidian-e2e-vaults/**",
      ".obsidian-e2e-instances/**",
      ".obsidian-e2e-artifacts/**",
    ],
  },
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,mts,cts}"],
    languageOptions: { globals: sharedGlobals },
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports" }],
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "prefer-const": "error",
    },
  },
  {
    files: ["src/**/*.{ts,mts,cts}"],
    ignores: ["src/**/*.test.ts"],
    plugins: { obsidianmd },
    rules: obsidianGuidelineRules,
  },
);
