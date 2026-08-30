# eval/

Deterministic evaluation, benchmark, and historical review records. **Not the paper voice.**

Nothing here is copied into `paper/` unless it is rewritten with opaque ids and no product names. Private provider-routing records are excluded from the public release tree.

| Path | What |
|---|---|
| `reviews/` | Historical independent review rounds. Each record is evidence only for the commit it names; it is not current release approval. |
| `bench/` | The deterministic three-layer kernel bench and its generated `RESULTS.md`. Numbers are kernel queries over the journals; the generators are simulated and the file says so. |
| `LOG.md` | **The research log.** Append-only, pre-registrations committed before each run, results appended after. The full account of E1–E8 and the corrections that followed review. Start here before citing any number from `bench/`, `generators/` or `realdefects/`. |
| `generators/` | Record/replay corpora of real generated code, and the run record for the one collection made so far. Vendor-free: no model or provider is named anywhere. |
| `realdefects/` | The real-defect study — BugsInPy bugs run as differentials against their own fixes. Eight hand-verified defects; no defensible detection rate, and `LOG.md` says why. |

## Reproducing the E8 hand adjudication

The committed E8 result was produced with Python 3.11,
`hypothesis==6.165.10`, and `lxml==6.0.2`. Install the pinned development
environment, then run the hand-check directly:

```bash
rm -rf /tmp/admissible-e8-v080
python3.11 -m venv /tmp/admissible-e8-v080
/tmp/admissible-e8-v080/bin/python -m pip install -e '.[dev]'
/tmp/admissible-e8-v080/bin/python eval/realdefects/e8_handcheck.py
rm -rf /tmp/admissible-e8-v080
```

The command fails closed if a runnable candidate cannot load or any claimed
hand separation does not execute. Its final `HANDCHECK_SUMMARY` reports
executed, separated, expected-negative, not-run, and failed case counts.
