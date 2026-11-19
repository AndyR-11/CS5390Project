# T1 + T2 integration

This file documents the initial capture-to-schema integration. For the later
multi-master lab, TCP reconstruction, verified labels and integrated detection,
see [integrated_ids/README.md](integrated_ids/README.md). Limitations below refer
to the initial `opcua_ids/chain_t1_t2.py` runner, which remains available unchanged.

This integration is based on the `opc` branch at commit
`1ff7557a5522cf6dbbf8f2faa09641ec4589e8f4`, checked against GitHub on
November 18, 2026. Its source files match the supplied OPC snapshot.
The changes are prepared on `paola/t1-t2-integration` for team review.

## Changes

- Added `opcua_ids/chain_t1_t2.py`: Paola's T1 groups raw payloads, then the
  existing `infer_boundaries`, `merge_fields`, and `assign_roles` functions run
  separately within each known training group. Unknowns are counted and skipped.
- Added four integration tests in `opcua_ids/test_chain_t1_t2.py`.
- Changed only the import in `modbus_ids/infer_roles.py` to support both package
  imports and the existing direct-script invocation. Its inference logic is unchanged.
- Paola's clustering algorithm and the existing detector logic are unchanged.

## Run from the project root

```bash
python -m pip install -r paola_t1/requirements.txt
python -m unittest paola_t1.test_clustering opcua_ids.test_chain_t1_t2 -v
python -m opcua_ids.chain_t1_t2 pcaps/opcua/opc_normal_only.pcapng --port 4840 --out integration_results/opc_t1_t2.json
```

The default chronological split trains T1 and T2 on the first 70% of normal
payloads. The remaining 30% are assigned using the frozen T1 model. Held-out
coverage does not evaluate the correctness of inferred T2 boundaries.
Use repeated `--test-pcap PATH` arguments to assign other captures without retraining.

## Verified locally on November 18, 2026

- 14 tests passed: 10 existing T1 tests plus four integration tests.
- Integration tests check that T2 receives each cluster separately in original
  order, schemas cover their payload length without gaps, input records are
  unchanged, rare training payloads are skipped, held-out data cannot retrain T1,
  and empty training input is rejected.
- Normal OPC UA capture: 195 client-to-server TCP payloads; 136 training,
  59 held out. Four training clusters contain 22, 44, 20, and 39 payloads;
  11 training payloads are unassigned. Each known cluster produces eight inferred
  field spans. These spans are not validated OPC UA fields.
- Held out: 56 of 59 assigned, three unknown (94.9% grouping coverage).
- Additional captures: invalid_node 8/8 unknown; write_no_read 11/11;
  value_jump 12/12; read_flood 60/60; session_flood 120/120.
  These are novelty counts, NOT attack detection rates. Session-specific bytes,
  message lengths and other differences may explain unknown assignments.
- Existing Modbus chain still runs: 1,982 requests, two clusters of 1,798 and
  184 requests. Each yields two field spans. Its existing reference scoring
  reports F1 0.57 for each cluster, on the same data used for inference and
  counting offset zero. This is not independent validation or OPC UA accuracy.

Results are in `integration_results/opc_t1_t2.json` and
`integration_results/modbus_existing_chain.json`.

## Remaining limits

The loader reads IPv4 TCP payloads without stream reassembly, deduplication or
application-message framing. A payload can contain a partial message or multiple
messages. Clustering by length can split the same semantic operation. The T2
merge and role functions use big-endian numeric heuristics and the existing
0.12 boundary threshold, previously selected on Modbus data. Their transfer to
OPC UA is unvalidated. Adjacent constant fields can still be merged incorrectly.

The output is a per-T1-cluster inference artifact. It is not compatible by
assumption with the existing OPC UA detector profile, which uses prefix-based
groups. Connecting inferred fields to detection and evaluating independently
labeled sessions remain separate work. This branch does not merge changes into
`main` or `opc`.
