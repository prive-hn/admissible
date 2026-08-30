"""Recorded generator samples: collect once, replay forever.

Nothing here calls a model, imports a vendor SDK, or touches the network. This
repository has no runtime dependencies and its evaluation is meant to replay
from committed bytes; a script that reached out to a provider would contradict
both, and would carry model names and prices that are stale the week after they
are written. Collection happens elsewhere, by whatever means the operator has,
and what arrives is plain text this module verifies and stores.


The bench needs a generator; the kernel needs determinism. A generator that is
a language model is not deterministic, so it cannot sit inside an evaluation
whose journals are meant to replay. Recording resolves that without weakening
either: samples are collected once, out of band, and what came back is
content-addressed and committed. Every later run reads the corpus, so the
numbers are reproducible by anyone, cost nothing to re-derive, and can be
audited against the artefacts they describe.

It is also what makes a comparison fair. The same targets, refuters and seeds
are applied to every corpus, so a difference in outcome is a difference in the
generator and nothing else.

One thing changes shape when a real model replaces the simulated generator.
`eval/bench` assigns each line a scenario -- honest, sloppy, unstable -- and
the sample is built to match, which is why its outcomes are close to
definitional. A recorded model corpus has no scenarios. What the model wrote
is what it wrote; which bucket it falls into is the gate's *finding*, not the
harness's input.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Callable

SCHEMA = "admissible/eval/sample-corpus/v1"
CORPUS_DIR = pathlib.Path(__file__).resolve().parent / "corpora"


def digest(source: bytes) -> str:
    return hashlib.sha256(source).hexdigest()


def corpus_path(model: str, target: str) -> pathlib.Path:
    safe = model.replace("/", "-")
    return CORPUS_DIR / f"{safe}.{target}.json"


def save(model: str, target: str, task: str,
         samples: list[dict], meta: dict | None = None) -> pathlib.Path:
    """Write one model's samples for one target.

    `task` should be the exact prompt text: it is hashed into the record
    because a corpus generated from a different prompt is a different
    experiment, and a comparison across models is only fair while that hash is
    equal. The corpora committed under `corpora/` pass a target label here
    instead (`spec:normpath`), so their hashes distinguish targets rather than
    instructions and the fairness check is inert for them.
    """
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    document = {
        "schema": SCHEMA,
        "model": model,
        "target": target,
        "task_sha256": hashlib.sha256(task.encode("utf-8")).hexdigest(),
        "task": task,
        "sample_count": len(samples),
        "samples": sorted(samples, key=lambda s: (s["line"], s["index"])),
        **(meta or {}),
    }
    path = corpus_path(model, target)
    path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
    return path


def load(model: str, target: str) -> dict:
    path = corpus_path(model, target)
    if not path.exists():
        raise FileNotFoundError(
            f"no corpus for model {model!r} target {target!r} at {path}. "
            "Collect samples per the corpus format in this directory's "
            "README, then ingest them with `corpus.ingest`.")
    document = json.loads(path.read_text())
    if document.get("schema") != SCHEMA:
        raise ValueError(f"{path} is not a {SCHEMA} document")
    for sample in document["samples"]:
        actual = digest(sample["source"].encode("utf-8"))
        if actual != sample["sha256"]:
            raise ValueError(
                f"{path}: sample line {sample['line']} index {sample['index']} "
                f"does not match its digest; the corpus has been edited")
    return document


def replay_generator(model: str, target: str) -> Callable[..., list[bytes]]:
    """A `generate`-shaped callable backed by a recorded corpus.

    Signature matches `eval.bench.bench.generate` so it drops into the same
    seam. `scenario` is accepted and ignored: a recorded corpus has none, and
    silently returning simulated samples for an unknown scenario would mix two
    experiments in one table.
    """
    document = load(model, target)
    by_line: dict[int, list[bytes]] = {}
    for sample in document["samples"]:
        by_line.setdefault(sample["line"], []).append(
            sample["source"].encode("utf-8"))

    def generate(target_: str, scenario: str, line_no: int, k: int) -> list[bytes]:
        if target_ != target:
            raise ValueError(f"corpus is for {target!r}, asked for {target_!r}")
        samples = by_line.get(line_no)
        if samples is None:
            raise KeyError(
                f"corpus has no line {line_no} for {target!r}; it holds "
                f"{len(by_line)} lines. Regenerate with the same line count.")
        if len(samples) < k:
            raise ValueError(
                f"line {line_no} has {len(samples)} samples, bench wants k={k}")
        return samples[:k]

    generate.corpus = document          # type: ignore[attr-defined]
    return generate


def ingest(raw: dict, model: str, target: str, task: str) -> pathlib.Path:
    """Turn a plain {line, index, source} listing into a verified corpus.

    Digests are computed here, never accepted from whoever produced the
    samples. A generator asserting its own content hash proves nothing, and no
    language model computes SHA-256 reliably in any case -- so the format asks
    for source text only and the digest is derived on the way in.
    """
    samples = []
    for entry in raw["samples"]:
        source = entry["source"]
        if not isinstance(source, str) or not source.strip():
            raise ValueError(f"empty source at line {entry.get('line')}")
        samples.append({
            "line": int(entry["line"]), "index": int(entry["index"]),
            "source": source, "sha256": digest(source.encode("utf-8")),
        })
    seen = {(s["line"], s["index"]) for s in samples}
    if len(seen) != len(samples):
        raise ValueError("duplicate (line, index) pair in the listing")
    return save(model, target, task, samples,
                meta={"ingested": True, "sample_count_in": len(samples)})


def stub_generator(sources: dict[int, list[str]]) -> Callable[..., list[bytes]]:
    """An in-memory generator for testing the seam without a model or a file."""

    def generate(target_: str, scenario: str, line_no: int, k: int) -> list[bytes]:
        return [s.encode("utf-8") for s in sources[line_no][:k]]

    return generate
