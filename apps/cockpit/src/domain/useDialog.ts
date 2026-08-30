import { useEffect, useRef } from "react";

const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

/**
 * Make a dialog behave like one: Escape closes it, Tab stays inside it, and
 * focus goes back where it came from.
 *
 * Every overlay here declared `role="dialog"` and most declared
 * `aria-modal="true"`, which tells assistive tech that everything outside is
 * hidden — while Tab walked straight out into that hidden content and Escape
 * did nothing. The declaration was the part that was true; this is the part
 * that was missing.
 *
 * Attach the returned ref to the dialog's own element.
 */
export function useDialog<T extends HTMLElement>(onClose: () => void) {
  const ref = useRef<T>(null);

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const node = ref.current;
    // Focus the first control rather than the container, so the first Tab
    // moves to the second control instead of into the page.
    const first = node?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? node)?.focus();

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== "Tab" || !node) return;
      const items = [...node.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
        (el) => el.offsetParent !== null || el === document.activeElement,
      );
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const edge = e.shiftKey ? items[0] : items[items.length - 1];
      if (document.activeElement === edge || !node.contains(document.activeElement)) {
        e.preventDefault();
        (e.shiftKey ? items[items.length - 1] : items[0]).focus();
      }
    };

    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      // Returning focus is what makes a dialog dismissible without a mouse:
      // otherwise closing one drops focus onto <body> and the next Tab starts
      // from the top of the document.
      opener?.focus?.();
    };
  }, [onClose]);

  return ref;
}
