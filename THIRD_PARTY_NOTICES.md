# Third-party notices

Admissible 0.8.0 has no third-party Python runtime dependency in
`admissible-core`; the Ready and Trust distributions depend only on the exact
`admissible-core==0.8.0` sibling, and the umbrella depends only on the three
exact Admissible siblings.

The optional browser cockpit is built from packages recorded in
`apps/cockpit/package-lock.json`. Its direct dependency inventory at this
release is:

| Package | Locked version | Declared license |
|---|---:|---|
| `@fontsource-variable/inter` | 5.3.0 | OFL-1.1 |
| `@fontsource/jetbrains-mono` | 5.3.0 | OFL-1.1 |
| `@radix-ui/colors` | 3.0.0 | MIT |
| `react` | 18.3.1 | MIT |
| `react-dom` | 18.3.1 | MIT |
| `@testing-library/jest-dom` | 6.9.1 | MIT |
| `@testing-library/react` | 16.3.2 | MIT |
| `@testing-library/user-event` | 14.6.5 | MIT |
| `@types/node` | 26.2.0 | MIT |
| `@types/react` | 18.3.31 | MIT |
| `@types/react-dom` | 18.3.7 | MIT |
| `@vitejs/plugin-react` | 6.1.0 | MIT |
| `jsdom` | 27.4.0 | MIT |
| `typescript` | 6.0.3 | Apache-2.0 |
| `vite` | 8.2.2 | MIT |
| `vitest` | 4.1.11 | MIT |

Transitive package versions, integrity hashes, and declared license identifiers
are preserved in the lockfile. `node_modules` is not committed or distributed
as repository source. A production distribution of compiled cockpit assets must
retain notices required by the dependency licenses.

## Vendored paper renderer

`paper/tools/pdf_create.py` is adapted from the Hermes Agent PDF skill by Nous
Research. The skill identifies Nous Research as author and MIT as its license.
The complete MIT permission and warranty notice is retained at the top of the
vendored file. This exception is also declared in `LICENSE.md`.

Research papers cite third-party publications. Citation does not incorporate or
relicense those publications. Bibliographic titles and author names are used
only to identify sources.

To reproduce the current dependency and vulnerability inventory:

```bash
npm ci --prefix apps/cockpit
npm audit --prefix apps/cockpit
```
