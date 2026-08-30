# Sample corpora

`eval/bench` drives the kernel with a *simulated* generator: each line is
assigned a scenario — honest, sloppy, unstable — and a sample is constructed to
match. That is why its figure is close to definitional. "Honest" is the
reference implementation plus a comment, checked against an oracle implementing
the same specification, so it seals 8/8 by construction rather than by
measurement. The bench says so, and licenses no claim about any generator's
defect rate.

This directory holds the other half: a format for samples produced by a real
generator, so the same kernel, refuters and seeds can be run against code
something actually wrote.

## Nothing here calls anything

No vendor SDK, no network, no credentials, no model names. This repository
declares zero runtime dependencies and its evaluation replays from committed
bytes; a script that reached out to a provider would contradict both, and would
carry names and prices stale a week later.

Collection happens **out of band**, by whatever means the operator has. What
arrives here is plain text. `corpus.py` verifies and stores it, and the bench
replays it forever after — offline, deterministic, free.

## Trust boundary

Digests are computed on ingest, never accepted from whoever produced the
samples. A generator asserting its own content hash proves nothing. So the
interchange format carries **source text only**, and `sha256` is derived on the
way in; `load` re-verifies every sample and refuses a corpus that has been
edited since.

## Interchange format

What collection must produce, per target:

```json
{
  "samples": [
    {"line": 0, "index": 0, "source": "def median(data):\n    ...\n"},
    {"line": 0, "index": 1, "source": "def median(data):\n    ...\n"}
  ]
}
```

- `line` — which work item, `0 .. lines-1`.
- `index` — which of the `k` samples for that line, `0 .. k-1`.
- `source` — the function definition alone. No prose, no fences, no imports.

Ingest it:

```python
import json, corpus
raw = json.load(open("collected.json"))
corpus.ingest(raw, model="<label>", target="median", task=TASK_TEXT)
```

`model` is a free-form label used only to name the file and to distinguish
corpora in a comparison; it carries no meaning to the code. `task` is meant to
be the exact instruction text, hashed into the record — a corpus collected from
a different instruction is a different experiment, and a comparison is only fair
while `task_sha256` matches across corpora.

**As committed, that check cannot fire.** The corpora in `corpora/` record
`task` as a target *label* (`spec:normpath`), not the instruction text, so the
four hashes differ by construction and carry no evidence about what any context
was asked. Ingesting with the real instruction text restores the check; until
then, "every context got the same instruction" is asserted rather than
recorded.

## Replaying one

```python
from corpus import replay_generator
generate = replay_generator("<label>", "median")   # matches bench.generate
```

Then `bench.run_target("median", generator=generate)`. The result records the
corpus's label, prompt digest and sample count under `generator`, because a
table that does not say where its samples came from is not a record of
anything.

## Why `k` samples per line must be independent

The bench asks for `k` samples per line and treats their agreement as evidence
— concordance is the gate's discord check. Samples drawn in one continuous
context are correlated: a generator asked for three implementations at once
tends to produce one implementation three times, or three deliberate variations
neither of which is what it would produce cold.

Either destroys the signal. Collect each sample independently, from a fresh
context. If that is impractical, the discord numbers from that corpus are not
meaningful and should not be reported.

## Limits

- **Wired into `bench.run()`.** A corpus run collapses the honest/sloppy/unstable buckets into a single `recorded` scenario (`eval/bench/bench.py`), since those labels are properties of the simulated generator and mean nothing for recorded samples; corpus provenance is recorded in the results.