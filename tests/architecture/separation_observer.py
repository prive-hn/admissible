"""The trusted observer: it watches one mutated test run and signs what it saw.

The harness judges a guard from a structured account of what a named test did:
which test ran, whether it failed, and with which exception and message.  That
account can only be produced inside the process running the test -- and that
process is running code this harness has deliberately broken.  If the same
process can also *deliver* the account, the harness is reading a verdict its
own subject wrote, and a mutant that wants a kill can simply say so.

So delivery is moved out.  Three processes, with the boundary between the
second and third being the point:

``harness``
    the parent.  It makes an anonymous pipe and a per-run key and nonce, hands
    both to the observer -- the pipe as an inherited descriptor, the key on the
    observer's standard input -- and afterwards accepts exactly one frame,
    carrying this run's nonce and authenticated with this run's key.
``observer``
    this module.  It runs from a sealed copy of itself outside the disposable
    clone, holds the only key, starts the test process, and derives the run's
    status from what it can observe from outside: the child's exit status and
    the single record frame on the child's standard output.  Anything
    ambiguous -- no frame, a second frame, a frame it cannot parse, a verdict
    that disagrees with the exit status -- it reports as a problem, which the
    parent reads as ``ERROR``.
``test process``
    the subject.  It has no descriptor on the channel, no key, no nonce and no
    path to anything the parent reads.  Its argv is the test ids and nothing
    else, its environment is the harness's allowlist, and its standard input
    is ``/dev/null``.  It can print whatever it likes on its own stdout; what
    it cannot do is make the parent believe a frame it wrote.

What this does *not* claim: the record's contents still originate inside the
test process, because "which assertion failed, and with what message" exists
nowhere else.  The claim is narrower, and checkable.  A tested process cannot
author the evidence the parent trusts -- it holds nothing the parent will
accept a frame on -- and it cannot *add* a record without the run becoming an
error, because a second frame on stdout is an ambiguity and ambiguity is not a
kill.  The recorder it would have to subvert instead captures its primitives
before a line of the clone is imported and keeps its state in a function's
locals, so replacing ``json``, ``open``, ``sys.stdout`` or ``unittest``'s
result classes and their methods changes nothing about what is recorded.

The honest residue: code that walks the interpreter's own frames could still
reach that recorder's locals in the process it shares with it.  The threat this
harness actually has is a bounded set of source mutations it wrote itself, not
a hostile peer on the machine, and against a hostile peer no in-process
recorder would be worth anything.  What is ruled out is the whole class of
accident and shortcut that made the earlier design wrong: a report path in
argv, a writable file the subject can find, machinery it can replace, and a
parent that believes a document its own subject produced.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import subprocess
import sys

#: The wire format of the one frame the parent will read.  Versioned so that a
#: parent and an observer that disagree about the format fail closed rather
#: than parsing each other's bytes optimistically.
FRAME_VERSION = "ADMISSIBLE-OBSERVER-1"

#: The statuses a record may carry.  A record with anything else in it is a
#: malformed frame, not a test result.
STATUSES = ("passed", "failed", "errored", "skipped")

#: Bounds on what one child may say, so that a mutation cannot make the report
#: unreadable -- or unbounded -- by failing very loudly.
MAX_TAIL = 1000
MAX_FIELD = 8000


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _tail(*streams: str) -> str:
    """The last few lines of the child's output, for a human to read."""

    joined = "".join(streams).strip()
    return " | ".join(line.strip() for line in joined.splitlines()[-4:]
                      if line.strip())[:MAX_TAIL]


def _problem(reason: str, **rest) -> dict:
    report = {"problem": reason, "timed_out": False, "returncode": None,
              "ran": 0, "records": [], "tail": ""}
    report.update(rest)
    return report


def _records_from(payload: dict, record_limit: int) -> tuple[list, str]:
    """The child's records, or why they are not usable as records."""

    rows = payload.get("records")
    if not isinstance(rows, list):
        return [], "the record frame carried no list of results"
    if len(rows) > record_limit:
        return [], (f"the record frame carried {len(rows)} results, more than "
                    f"the {record_limit} one run may report")
    records = []
    for row in rows:
        if not isinstance(row, dict):
            return [], "the record frame carried a result that is not a record"
        entry = {}
        for field in ("test", "status", "exception", "message", "subtest"):
            value = row.get(field, "")
            if not isinstance(value, str) or len(value) > MAX_FIELD:
                return [], (f"the record frame carried a {field} that is not "
                            "a bounded string")
            entry[field] = value
        if entry["status"] not in STATUSES:
            return [], (f"the record frame carried the status "
                        f"{entry['status']!r}, which is not a test result")
        records.append(entry)
    return records, ""


def observe(config: dict) -> dict:
    """Run the tests named in ``config`` and report what could be observed."""

    marker = config["marker"]
    timeout = config["timeout"]
    command = [config["executable"], "-B", "-s", "-c", config["runner"],
               *config["tests"]]
    try:
        completed = subprocess.run(
            command, cwd=config["cwd"], env=config["environment"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, close_fds=True,
            start_new_session=True)
    except subprocess.TimeoutExpired as expired:
        return _problem(f"the run did not finish inside {timeout}s",
                        timed_out=True,
                        tail=_tail(_text(expired.stdout or b""),
                                   _text(expired.stderr or b"")))
    except (OSError, subprocess.SubprocessError) as error:
        return _problem(f"the suite could not be started: {error}")

    out, err = _text(completed.stdout), _text(completed.stderr)
    tail = _tail(out, err)

    # Exactly one frame, or none of this is evidence.  A second one is not a
    # tie to be broken by preferring the first: it is a run in which something
    # other than the recorder wrote a record, and there is no way from out here
    # to tell which of the two that was.
    seen = out.count(marker)
    if seen == 0:
        return _problem(
            "the run wrote no record frame, so nothing it did can be judged: "
            "the child died before the recorder reached the end", tail=tail,
            returncode=completed.returncode)
    if seen > 1:
        return _problem(
            f"the run wrote {seen} record frames where exactly one is the "
            "protocol; a second frame is something other than the recorder "
            "writing a record, and from out here the two cannot be told apart",
            tail=tail, returncode=completed.returncode)

    line = next(item for item in out.splitlines() if marker in item)
    if not line.startswith(marker + " "):
        return _problem(
            "the record frame was embedded in other output rather than "
            "written as its own line", tail=tail,
            returncode=completed.returncode)
    try:
        payload = json.loads(base64.b64decode(line[len(marker) + 1:].strip(),
                                              validate=True))
    except (ValueError, binascii.Error) as error:
        return _problem(f"the record frame could not be read: {error}",
                        tail=tail, returncode=completed.returncode)
    if not isinstance(payload, dict):
        return _problem("the record frame is not a report", tail=tail,
                        returncode=completed.returncode)

    ran, successful = payload.get("ran"), payload.get("successful")
    if not isinstance(ran, int) or isinstance(ran, bool) or ran < 0:
        return _problem("the record frame carried no count of tests run",
                        tail=tail, returncode=completed.returncode)
    if not isinstance(successful, bool):
        return _problem("the record frame carried no verdict", tail=tail,
                        returncode=completed.returncode)
    if payload.get("truncated"):
        return _problem(
            "the run reported more results than one report may carry, so what "
            "came back is not the whole of what happened", tail=tail,
            returncode=completed.returncode)
    crashed = payload.get("crashed") or ""
    if crashed:
        return _problem(
            f"the run did not complete as a suite: {str(crashed)[:MAX_FIELD]}",
            tail=tail, returncode=completed.returncode)
    records, why = _records_from(payload, config["record_limit"])
    if why:
        return _problem(why, tail=tail, returncode=completed.returncode)

    # The one thing about the run the child did not get to write down.  A
    # report claiming a failure from a process that exited 0, or the reverse,
    # is not a report about this run.
    if successful != (completed.returncode == 0):
        return _problem(
            f"the run exited {completed.returncode} while reporting "
            f"{'success' if successful else 'failure'}; the record frame and "
            "the process disagree about what happened", tail=tail,
            returncode=completed.returncode)

    return {"problem": "", "timed_out": False,
            "returncode": completed.returncode, "ran": ran,
            "records": records, "tail": tail}


def sealed_frame(key: bytes, nonce: str, report: dict) -> bytes:
    """``report``, bound to this run and authenticated with this run's key."""

    body = base64.b64encode(json.dumps(dict(report, nonce=nonce),
                                       sort_keys=True,
                                       separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(key, nonce.encode("ascii") + b"." + body,
                         hashlib.sha256).hexdigest()
    return b" ".join((FRAME_VERSION.encode("ascii"), nonce.encode("ascii"),
                      signature.encode("ascii"), body)) + b"\n"


def main() -> int:
    channel = int(sys.argv[1])
    config = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    key = bytes.fromhex(config["key"])
    nonce = config["nonce"]
    try:
        report = observe(config)
    except BaseException as error:  # noqa: BLE001 - the observer never guesses
        report = _problem(
            f"the observer itself failed: {type(error).__name__}: "
            f"{str(error)[:MAX_FIELD]}")
    os.write(channel, sealed_frame(key, nonce, report))
    os.close(channel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
