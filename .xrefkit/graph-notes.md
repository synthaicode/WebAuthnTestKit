# Structure Graph Profile — WebAuthnTestKit

This `.xrefkit/` directory persists the **requirement-independent** parts of the
structure-graph backstop for this repository: the relation/classification layer
that XDDP's *Where* step (spec-out → traceability matrix) traverses.

Design reference: XRefKit `knowledge/source_analysis/160_structure_graph_tm_backstop.md`
(xid `163AD9936979`).

## Persisted here (requirement-independent)

| File | Holds |
|------|-------|
| `graph-profile.json` | identity, summary, hub classification, name-coupling classification, external-boundary definition |
| `graph-rules.yml` | traversal / pruning rules |
| `graph-baseline.json` | accepted baseline for drift detection |
| `graph-notes.md` | this file |

## NOT persisted here (per-change artifacts)

- change-requirement traceability matrix (TM)
- impacted-boundary list
- per-PR traversal results
- transient seeds

## Profile summary

Type-coupled repository. The change centre is `VirtualAuthenticator` (ctor
fan-in 17; `MakeCredential` / `GetAssertion` the two ceremony entries). Name
coupling is a **minor** axis — WebAuthn protocol JSON field names (`base64url`,
`public-key`, `username`, `challenge`) shared across encode/decode/test members —
so `name_coupling.required_for_tm = false`. The call + type graph carries most
impact; tests are pruned as transit.

## Key scheme

Nodes keyed by Roslyn documentation-comment id (DocID). Deterministic, stable
across body-only edits.
