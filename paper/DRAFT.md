# Fail-closed class dispatch

**Class-admitted work, data-plane bind. This machine has no leftover-hop edge.**

Roque Briceño  
Version 0.8.1. 4 September 2026.
Licensed under [CC BY 4.0](../LICENSES/CC-BY-4.0.txt).

## Abstract

A specialized model fleet is a checkable claim only if a work item of class $c$ cannot complete a stage on a specialist or model outside the policy for $c$.

Fail-closed class dispatch is that check: a work item carries a class and a frozen body; a policy gives each class an allow set $\pi(c)$ and a deny set $\delta(c)$; and each specialist $a$ is bound to one API model identity $\phi(a)$. A stage may run only after a well-formed admit of some $a \in \pi(c)\setminus\delta(c)$, and only with executed model $\mathrm{norm}(\phi(a))$; if that bind cannot be served, the stage fails closed and the failure is published. Retry, where there is one, is the same item, the same class, a specialist not yet tried — it does not search a leftover fallback list.

This is Clark–Wilson integrity applied to LLM binds, not a new access-control algebra: allow/deny, fail-safe defaults and dual control are old. The added obligations are three — $\phi$ is the identity Observe recorded from the inference client, leftover fallback is not an edge in this table, and the event contract is the witness set. An accidental hop is in scope; an adversarial worker that forges Observe is not.

Safety invariants hold on the abstract machine under stated enforcer obligations; a second envelope pins project state, accepted memory, instructions, agent, exact model, context policy, cache identity and steering at each gate attempt, extending the same fail-closed rule from model identity to context identity without rebuilding the worker's tools or session system. Item liveness does not hold. There is no quality theorem and no empirical table in this draft.

## 1. Problem

Routing, cascades and mixture-of-agents optimize score or spend (Chen et al., 2023; Ong et al., 2024; Wang et al., 2024); mixture-of-experts is a learned gate inside one network (Jacobs et al., 1991; Shazeer et al., 2017); orchestration says who calls whom. None of them forbids a hop to an unbound model when the bound provider is down, and none of them treats a model that refuses a class as illegal rather than low-scoring.

The sentence “we run specialists” is then unfalsifiable: the control plane can name one model while the data plane calls another; a 403 can look like work still in progress; a reviewer can be the author.

The required property is class integrity: a pass record lies in $\pi(c)\setminus\delta(c)$ and uses $\phi(a)$. The process is the smallest transition system that keeps that property and refuses the leftover hop.

## 2. Objects

A **work item** has class $c$, charge, frozen body hash, author set, required-stage list $\mathrm{Required}(c)$, and status $\mathrm{open}\mid\mathrm{failed}\mid\mathrm{accepted}$.

$\pi(c)$ and $\delta(c)$ are disjoint. On a check stage the effective allow set is $\pi_{\mathrm{chk}}(c,\mathrm{authors})=\pi(c)\setminus\mathrm{authors}$.

$\phi:A\to M$ maps a specialist to an API identity; display strings are compared after $\mathrm{norm}$.

$u(m)=0$ iff bind time returns 401, 403, 404, 429, exhausted, or not_found.

$\mathrm{tried}$ is the set of specialists already admitted on this stage.

A stage is **well-formed** only if a control event names class, specialist, declared model, and body hash. Prose that mentions a name is not a stage.

**Fail closed** means: publish a `fail_closed` decision; next is ask, retry in $\pi(c)\setminus\delta(c)\setminus\mathrm{tried}$, or stop.

An **accepted artifact** exists only when every stage in $\mathrm{Required}(c)$ has passed. The **store** accepts only accepted artifacts.

## 3. Process

1. Open a well-formed work item.
2. Admit $a\in\pi^*(c)\setminus\delta(c)\setminus\mathrm{tried}$. If none, fail closed.
3. Bind. Writes $m_{\mathrm{decl}}=\phi(a)$. If $u(\phi(a))=0$, fail closed. Does not write $m_{\mathrm{exec}}$.
4. Observe. Copies $m_{\mathrm{exec}}$ from the provider call (A1).
5. Pass only if $\mathrm{norm}(m_{\mathrm{exec}})=\mathrm{norm}(m_{\mathrm{decl}})$; else PassRefuse (F1).
6. When $\mathrm{Required}(c)$ is covered, Accept into the store.

A death watchdog outside the worker records death while Running (A2, A9). Close publishes.

## 4. What holds

Proofs: `PROOFS.md`. Machine: `fcd/core.py`. Checks: `tests/`.

Bind writes the declared identity only and Observe writes the executed one, so I1 is non-vacuous. Under A0–A9, I1–I6, I8 and I9 are inductive; I7 bounds the Admit count; and under A10–A13, I10–I17 prove work-snapshot pinning, package/receipt binding, steering scope, attempt-local cache identity and accepted-only memory promotion. Ask may idle.

The leftover-hop picture is an illustration, not a corollary.

## 5. Context, memory and cache envelope

A project has an accepted snapshot $P_v$ and accepted semantic memory $K_v$, and a work item pins $(P_v,K_v)$ at Open; its raw transcripts, candidate reasoning and failed attempts remain evidence — they are not project memory.

A gate attempt carries a monotonic counter and an unpredictable nonce, and at Admit it freezes

$$X_{g,a}=(attempt,P_v,K_v,W_r,G_r,A_r,specialist,M_r,I_h,C_p,T_h,Q_c,S_0,channel).$$

Here $M_r$ is the exact provider/API model reference, $I_h$ the layered instruction hash, $C_p$ the selector over context categories, $T_h$ the binding to tool authority, $Q_c$ the FCD attempt-local cache policy, and $S_0$ the steering already present at Admit; a base-envelope change closes the attempt and creates a new nonce.

FCD builds canonical context bytes $B_{g,a}$ from `include minus exclude`, where exclude wins, and the adapter independently hashes the bytes it submits; Pass requires the observed package hash, attempt/nonce, executor/run, latest steering continuation and executed-model receipt all to match the current envelope. A previous-attempt receipt cannot authorize a new attempt.

The package modes are `project_shared`, `fresh_scoped`, `fresh_blind` and `contract_only`; a `fresh_blind` review excludes author transcript, reasoning, prior verdict and unaccepted memory, and forbids executor continuity. Continuing or forking an opaque executor session is a declared adapter capability, not an FCD-owned session store.

Live steering is an ordered stream outside the frozen base envelope, each event addressing project, work, gate, stage, artifact, evidence or failure scope; Pass requires acknowledgement of the latest continuation hash. Steering cannot write accepted state or sibling work.

FCD cache stays attempt-local and clears at Admit/Close; provider or executor prefix/session reuse is reported telemetry, not Pass authority — which separates semantic context from an optimization.

Only Accept may promote a reviewed knowledge delta, and promotion is a serialized compare-and-swap on the exact project/memory head; if another accepted item advances the head, stale active work requires a signed impact review. `continue_pinned` binds that review to one exact new head — another advance invalidates it — and `refresh` does not authorize the stale final gate.

These are process theorems about manifests, receipts and state transitions; they do not prove physical prompt isolation, hidden executor residue, model quality or impact-review correctness.

## 6. Faults

Each fault is a forbidden transition, not a metaphor.

| Id | Forbidden step |
|---|---|
| F1 | Pass with $\mathrm{norm}(m_{\mathrm{exec}})\neq\mathrm{norm}(\phi(a))$ |
| F2 | Two specialists, one runtime instance (needs an instance field to measure) |
| F3 | After $u=0$, another call without fail-closed, or a call outside unused allow |
| F4 | Running exit with no published close |
| F5 | $\phi(a)$ not an API identity |
| F6 | Pass with $a\in\delta(c)$ |
| F7 | Check admit with $a\in\mathrm{authors}$ |
| F8 | Run without a well-formed stage |
| F9 | Stop in chat with status not accepted |
| F10 | Same id, class changes; or retry of $a\in\mathrm{tried}$ |

Weight-sharing across specialists is extra config; it is not in I6.

## 7. Measurement

A **named cut** is $[t_0,t_1]$ with a window $W$ taken from the class reply-time distribution (exclude $ts>t_1-W$), and $\pi,\delta,\phi$ are evaluated **as-of event $ts$**; a pinned policy version is only a default when no as-of row exists.

- Misbind: first observed bind attempt per stage where $\mathrm{norm}(m_{\mathrm{exec}})\neq\mathrm{norm}(\phi(a))$ — an observation-gap / A1-breach rate, not F1 (F1 requires Pass); never publish it without silent-fail.
- Silent fail: well-formed stages with no `decide`/`accept` within $W$, plus work items that `open` and never emit a stage. Fail-closed counts as published.
- Bleed: assigned $a$ outside $\pi^*(c)$ as-of $ts$ (use $\pi_{\mathrm{chk}}$ on check stages). Pair with silent-fail.
- Time-to-stage: duration from well-formed stage to `decide` or `accept`, as a right-censored survival paired with $1-$ silent-fail. Not a mean.

Zeros on misbind, bleed and silent-fail are a proof that those faults did not fire only if `stage` is write-ahead and `call`/`decide` are total; otherwise they are estimates biased clean. Schema: `../metrics/SCHEMA.md`. No numbers here.

## 8. Reference implementation

The repository includes the acceptance kernel, the context authority, an immutable project/evidence atlas, language-neutral schemas, an execution-adapter boundary and a project/work/artifact cockpit. The cockpit loads and verifies a local/GitHub project before intake, and every work line stays selectable under its capability: a gate shows agent instructions and authority, exact provider/API model, context mode and exact-route readiness before Admit — an unavailable route cannot start — and after Admit the same tray locks to package/model/steering receipts. Questions are anchored to their node; drift review and multi-scope steering remain inside the work surface.

The implementation does not widen the theorem: an execution adapter preserves an existing worker's tools, session implementation and provider cache, but cannot Pass, Accept or promote memory, and a skin is a read-only projection that cannot hide model/context/receipt state or write policy, journal or store. The artifact iframe is sandboxed. `fcd` remains the only writer of accepted state.

Replay, policy-version pinning, and the DAG gate make a project many dependent lines over time: a line opens only on accepted dependencies and finishes under the policy version pinned at Open.

## 9. Related work

Clark and Wilson (1987) already have constrained data items, transformation procedures, a certification relation, integrity verification and mandatory separation of duty: a work item is a CDI, a bound specialist is a TP, and Accept is a validated write.

Saltzer and Schroeder (1975) name fail-safe defaults; deny-override is standard MAC/RBAC; Thomas and Sandhu (1997) bind permission to a task instance. F1/F2/F5 are TOCTOU / control-plane versus data-plane divergence, and F7 is also LLM-as-judge self-preference.

MoE, MoA, FrugalGPT, RouteLLM and MoMA optimize a different objective, and orchestrator-worker (Anthropic, 2024) is a topology. Topology is not the process.

## 10. Limits

There is no dataset here, no quality theorem, and no item liveness. I1–I6, I8 and I9 are proved on the Observe machine; I7 is a bound; and I10–I17 prove FCD-owned envelope, manifest, receipt, cache and promotion transitions. A1/A2 and A10–A12 are observation/trust assumptions, and a package receipt proves submitted-byte equality under an honest adapter, not the absence of hidden executor context. Provider fidelity, cache semantic neutrality and impact-review correctness are not proved. The hop remark is an illustration.

## 11. References

Anthropic. How we built our multi-agent research system. Anthropic Engineering, 2024.

Chen, L., Zaharia, M., and Zou, J. FrugalGPT. [arXiv:2305.05176](https://arxiv.org/abs/2305.05176), 2023.

Clark, D. D., and Wilson, D. R. A comparison of commercial and military computer security policies. IEEE Symposium on Security and Privacy, 1987.

Guo, X., et al. Towards Generalized Routing: MoMA. [arXiv:2509.07571](https://arxiv.org/abs/2509.07571), 2025.

Jacobs, R. A., Jordan, M. I., Nowlan, S. J., and Hinton, G. E. Adaptive mixtures of local experts. Neural Computation, 1991.

Ong, I. et al. RouteLLM. 2024.

Saltzer, J. H., and Schroeder, M. D. The protection of information in computer systems. Proceedings of the IEEE, 1975.

Shazeer, N. et al. The sparsely-gated mixture-of-experts layer. ICLR, 2017.

Thomas, R. K., and Sandhu, R. S. Task-based authorization controls (TBAC). 1997.

Wang, J. et al. Mixture-of-Agents Enhances Large Language Model Capabilities. [arXiv:2406.04692](https://arxiv.org/abs/2406.04692), 2024.
