# data/

Local output of `fcd.metrics` over a named cut. Not committed.

```python
from fcd.metrics import rates, survival
# rates(events, t0, t1, W, policy) -> misbind, silent_fail, bleed
# survival(events, t0, t1, W) -> n, durations, censored
```

Write JSONL here if you persist a journal. Historical mixed logs are not rates.
