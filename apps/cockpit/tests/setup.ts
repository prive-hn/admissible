import "@testing-library/jest-dom/vitest";

// jsdom lacks EventSource; the client falls back to polling when it's absent.
// Provide a stub that immediately errors so tests exercise the polling path.
class StubEventSource {
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  constructor(_url: string) {
    setTimeout(() => this.onerror?.(new Event("error")), 0);
  }
  close() {}
}
// @ts-expect-error test shim
globalThis.EventSource = StubEventSource;
