import type { CockpitState } from "./types";

/**
 * Demo state used ONLY when the API is unreachable. It is labeled
 * "Demo disconnected" in the UI. Every stage/failure here mirrors a real
 * fail-closed class dispatch trace so the instrument reads truthfully even
 * offline: a write stage that holds, a check stage that broke on an F1
 * mismatch and published, and a question that pauses a third item.
 */
export function makeDemoState(): CockpitState {
  return {
    connection: "demo-disconnected",
    revision: 0,
    settings: {
      versionLabel: "settings v0",
      acceptanceMode: "strict-match",
      intakeMode: "class-inferred",
      repairMode: "retry-in-allow-set",
    },
    atlas: {
      outcome: { active: 2, accepted: 1, degraded: 1, question: 1 },
      capabilities: [
        {
          id: "cap-checkout",
          name: "Checkout integrity",
          outcome: { active: 1, accepted: 1, degraded: 1, question: 0 },
          components: [
            {
              id: "cmp-charge",
              name: "Charge authorization",
              workItemIds: ["W1"],
              outcome: { active: 1, accepted: 0, degraded: 0, question: 0 },
            },
            {
              id: "cmp-refund",
              name: "Refund path",
              workItemIds: ["W2"],
              outcome: { active: 0, accepted: 0, degraded: 1, question: 0 },
            },
            {
              id: "cmp-receipt",
              name: "Receipt store",
              workItemIds: ["W4"],
              outcome: { active: 0, accepted: 1, degraded: 0, question: 0 },
            },
          ],
        },
        {
          id: "cap-identity",
          name: "Identity binding",
          outcome: { active: 1, accepted: 0, degraded: 0, question: 1 },
          components: [
            {
              id: "cmp-session",
              name: "Session admission",
              workItemIds: ["W3"],
              outcome: { active: 1, accepted: 0, degraded: 0, question: 1 },
            },
          ],
        },
      ],
    },
    questions: [
      {
        id: "Q1",
        workItemId: "W3",
        stageId: "W3.1",
        prompt:
          "The bind for the check stage came back unusable (F3). Retry inside the allow set, or stop this line?",
        context:
          "Session admission, check stage. Author 'alice' is excluded from the check allow set by dual control (I6).",
        allowFreeText: true,
        options: [
          { value: "retry:carol", label: "Retry with carol", hint: "vendorC:model-c" },
          { value: "retry:dave", label: "Retry with dave", hint: "vendorD:model-d" },
          { value: "stop", label: "Stop the line", hint: "fail closed, published" },
        ],
      },
    ],
    workItems: [
      {
        id: "W1",
        title: "Authorize charge before capture",
        cls: "impl",
        status: "open",
        policyVersion: "v0",
        pointer: 1,
        dependsOn: [],
        authors: ["alice"],
        openQuestionId: null,
        stages: [
          {
            id: "W1.0",
            kind: "write",
            name: "w1",
            pc: "Passed",
            specialist: "alice",
            declaredModel: "vendorA:model-a",
            executedModel: "vendorA:model-a",
            allowSet: ["alice", "carol"],
            tried: ["alice"],
            sentence: "Write stage held: declared and executed model matched, alice is now an author.",
            evidence: [
              { id: "W1.0-e1", kind: "stage", label: "Admitted alice", detail: "declared vendorA:model-a", journalIndex: 1 },
              { id: "W1.0-e2", kind: "bind", label: "Bind usable", detail: "m_decl = vendorA:model-a", journalIndex: 2 },
              { id: "W1.0-e3", kind: "call", label: "Observe", detail: "executed vendorA:model-a", journalIndex: 3 },
              { id: "W1.0-e4", kind: "decide", label: "Pass", detail: "norm(exec) == norm(decl)", journalIndex: 4 },
            ],
          },
          {
            id: "W1.1",
            kind: "check",
            name: "c1",
            pc: "Running",
            specialist: "carol",
            declaredModel: "vendorC:model-c",
            executedModel: null,
            allowSet: ["carol"],
            tried: ["carol"],
            sentence: "Check stage is running under carol; awaiting the provider's executed-model report.",
            evidence: [
              { id: "W1.1-e1", kind: "stage", label: "Admitted carol", detail: "check excludes author alice (I6)", journalIndex: 5 },
              { id: "W1.1-e2", kind: "bind", label: "Bind usable", detail: "m_decl = vendorC:model-c", journalIndex: 6 },
            ],
          },
        ],
      },
      {
        id: "W2",
        title: "Refund reverses the original capture",
        cls: "impl",
        status: "failed",
        policyVersion: "v0",
        pointer: 1,
        dependsOn: [],
        authors: ["carol"],
        openQuestionId: null,
        stages: [
          {
            id: "W2.0",
            kind: "write",
            name: "w1",
            pc: "Passed",
            specialist: "carol",
            declaredModel: "vendorC:model-c",
            executedModel: "vendorC:model-c",
            allowSet: ["alice", "carol"],
            tried: ["carol"],
            sentence: "Write stage held under carol.",
          },
          {
            id: "W2.1",
            kind: "check",
            name: "c1",
            pc: "Closed",
            specialist: "alice",
            declaredModel: "vendorA:model-a",
            executedModel: "vendorB:model-b",
            allowSet: ["alice"],
            tried: ["alice"],
            sentence: "Check stage broke: the provider executed a different model than was bound (F1). Published, no hop.",
            failure: {
              fault: "F1",
              whatHappened:
                "The check stage bound vendorA:model-a but the provider reported it executed vendorB:model-b. The Pass guard requires norm(m_exec) == norm(m_decl); the mismatch closed the stage.",
              whatRemainsSafe:
                "Nothing was accepted. The store is untouched — Accept is the only writer and it never ran. The failure was published to the journal; no leftover result was hopped to another model.",
              impact: {
                observed: [
                  "Check stage W2.1 closed with fault F1.",
                  "The refund line W2 is marked failed and did not reach the store.",
                ],
                reachable: [
                  "Any line depending on W2 cannot open (DAG gate refuses non-accepted dependencies).",
                ],
                unknown: [
                  "Whether the executed vendorB model would have passed the check on its own — out of scope; the bind was to vendorA.",
                ],
              },
              evidence: [
                { id: "W2.1-e1", kind: "stage", label: "Admitted alice", detail: "declared vendorA:model-a", journalIndex: 7 },
                { id: "W2.1-e2", kind: "bind", label: "Bind usable", detail: "m_decl = vendorA:model-a", journalIndex: 8 },
                { id: "W2.1-e3", kind: "call", label: "Observe", detail: "executed vendorB:model-b (on_bind=false)", journalIndex: 9 },
                { id: "W2.1-e4", kind: "decide", label: "Fail closed F1", detail: "result=fail_closed next=ask", journalIndex: 10 },
              ],
              recovery: [
                { label: "Retry check with alice", action: "retry", specialist: "alice", hint: "re-bind and re-observe" },
                { label: "Ask the operator", action: "pause", hint: "open a question on this stage" },
                { label: "Discard the line", action: "discard", hint: "stop, remain fail-closed" },
              ],
            },
            evidence: [
              { id: "W2.1-e1", kind: "stage", label: "Admitted alice", detail: "declared vendorA:model-a", journalIndex: 7 },
              { id: "W2.1-e3", kind: "call", label: "Observe", detail: "executed vendorB:model-b", journalIndex: 9 },
              { id: "W2.1-e4", kind: "decide", label: "Fail closed F1", detail: "next=ask", journalIndex: 10 },
            ],
          },
        ],
      },
      {
        id: "W3",
        title: "Bind a session to one model for its lifetime",
        cls: "impl",
        status: "open",
        policyVersion: "v0",
        pointer: 1,
        dependsOn: [],
        authors: ["alice"],
        openQuestionId: "Q1",
        stages: [
          {
            id: "W3.0",
            kind: "write",
            name: "w1",
            pc: "Passed",
            specialist: "alice",
            declaredModel: "vendorA:model-a",
            executedModel: "vendorA:model-a",
            allowSet: ["alice", "carol"],
            tried: ["alice"],
            sentence: "Write stage held under alice.",
          },
          {
            id: "W3.1",
            kind: "check",
            name: "c1",
            pc: "Closed",
            specialist: "carol",
            declaredModel: "vendorC:model-c",
            executedModel: null,
            allowSet: ["carol", "dave"],
            tried: ["carol"],
            sentence: "Bind came back unusable (F3); the line is paused on a question for the operator.",
            failure: {
              fault: "F3",
              whatHappened:
                "The bind u(φ(carol)) reported the model was not usable at bind time. The stage closed and published before any provider call.",
              whatRemainsSafe:
                "No execution occurred, nothing was observed, and the store is untouched. The line is paused pending a decision inside the allow set.",
              impact: {
                observed: ["Check stage W3.1 closed with fault F3 (bind unusable)."],
                reachable: ["carol is now in the tried set for this stage and cannot be re-admitted."],
                unknown: ["Whether dave's bind will be usable — not yet attempted."],
              },
              evidence: [
                { id: "W3.1-e1", kind: "stage", label: "Admitted carol", detail: "declared vendorC:model-c", journalIndex: 6 },
                { id: "W3.1-e2", kind: "decide", label: "Fail closed F3", detail: "result=fail_closed next=retry", journalIndex: 7 },
              ],
              recovery: [
                { label: "Retry with dave", action: "retry", specialist: "dave", hint: "next in allow set" },
                { label: "Stop the line", action: "discard", hint: "allow set nearly exhausted" },
              ],
            },
          },
        ],
      },
      {
        id: "W4",
        title: "Persist the receipt only via Accept",
        cls: "impl",
        status: "accepted",
        policyVersion: "v0",
        // The same record the live server projects: sealed at measured
        // power, concordance visibly unmeasured at k=1, residual named.
        admissibility: {
          layer: "IRC",
          sealed: true,
          mediated: true,
          admissible: true,
          impeached: false,
          tainted: false,
          failure: null,
          sentence:
            "Sealed: survived the pinned refuter at measured power 1; concordance is (1, 1) — unmeasured at k=1.",
          powerMin: 1,
          k: 1,
          agreeing: 1,
          residual: [["meets the operator's intent", "check_stage"]],
          trackRecords: null,
        },
        pointer: 1,
        dependsOn: [],
        authors: ["alice", "carol"],
        openQuestionId: null,
        stages: [
          {
            id: "W4.0",
            kind: "write",
            name: "w1",
            pc: "Passed",
            specialist: "alice",
            declaredModel: "vendorA:model-a",
            executedModel: "vendorA:model-a",
            sentence: "Write stage held under alice.",
          },
          {
            id: "W4.1",
            kind: "check",
            name: "c1",
            pc: "Passed",
            specialist: "carol",
            declaredModel: "vendorC:model-c",
            executedModel: "vendorC:model-c",
            sentence: "Check stage held under carol; the item was accepted into the store.",
          },
        ],
      },
    ],
  };
}
