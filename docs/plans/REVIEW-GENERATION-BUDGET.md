# Review-generation budget (operator fence)

Not a kernel machine. Family P3(b).

Default allow set: **2** generations per change (`--budget 2`).

Exhaustion is Closed. To continue:

```text
review-generation-fence.py open ... \
  --override-budget --new-budget N --override-reason "..."
```

`N` must be **greater than used**. The reason plus new budget is a new admit. A predecessor review found that an override which only skipped the check was unsafe; that private PR identity is not part of the clean public history.

Truncation / missing report / timeout:

```text
review-generation-fence.py unable --repo ... --pr ... --reason "..."
```

Marks the in-flight generation `unable`. The slot stays consumed.

A generation that should forbid n+1 is Closed, not an invitation to override without `--new-budget`.
