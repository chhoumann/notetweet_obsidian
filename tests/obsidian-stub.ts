// Minimal Obsidian API stubs so Vitest can resolve `import ... from "obsidian"`.
// Extend as tests require. This file is intentionally excluded from lint.
export class Notice {
  constructor(_message: string | DocumentFragment, _timeout?: number) {}
  setMessage() { return this; }
  hide() {}
}
export function requestUrl(_req: unknown): unknown {
  throw new Error("requestUrl is not stubbed in tests");
}
export const moment = () => ({ format: () => "" });
export class Modal {
  app: unknown;
  contentEl: Record<string, unknown> = {};
  constructor(app: unknown) { this.app = app; }
  open() {}
  close() {}
  onOpen() {}
  onClose() {}
}
export class Setting {
  constructor(_containerEl: unknown) {}
  setName() { return this; }
  setDesc() { return this; }
  setHeading() { return this; }
  addText() { return this; }
  addTextArea() { return this; }
  addToggle() { return this; }
  addButton() { return this; }
  addExtraButton() { return this; }
  addComponent() { return this; }
}
export class PluginSettingTab {
  app: unknown;
  plugin: unknown;
  containerEl: Record<string, unknown> = {};
  constructor(app: unknown, plugin: unknown) { this.app = app; this.plugin = plugin; }
}
export class Plugin {}
export class Component {}
export class TextComponent { inputEl: Record<string, unknown> = {}; setValue() { return this; } getValue() { return ""; } setPlaceholder() { return this; } onChange() { return this; } }
export class ButtonComponent { setButtonText() { return this; } setCta() { return this; } onClick() { return this; } }
export class SecretComponent { constructor(_app?: unknown, _el?: unknown) {} setValue() { return this; } onChange() { return this; } }
export class TFile {}
export class TFolder {}
export class MarkdownView {}
export class Editor {}
export class App {}
