import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { applySkinTokens, instrumentSkin } from "./skins/skin";
import { applyViewPrefs, readViewPrefs } from "./domain/viewPrefs";
// Self-hosted and bundled: the cockpit makes no network request for a face, so
// it reads the same on a machine with no route to the internet. A skin may
// point --font-sans/--font-mono elsewhere; these are what the references use.
import "@fontsource-variable/inter";
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-500.css";

import "./styles.css";

applySkinTokens(instrumentSkin);
// Before React mounts, so first paint is already at the operator's own text
// size and density rather than snapping to them once an effect runs.
applyViewPrefs(readViewPrefs());

const el = document.getElementById("root");
if (!el) throw new Error("missing #root");
createRoot(el).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
