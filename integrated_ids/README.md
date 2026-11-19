# Integrated local lab and evaluation

This extends the initial T1/T2 adapter. It adds a reproducible local experiment,
not a production IDS. All live sockets bind or connect to `127.0.0.1` only.


## What is implemented

| Requested task | Implementation and verification |
| --- | --- |
| OPC UA lab + T1 + inference + detection | `run_lab.py` captures the live lab and calls `evaluate.py`. The latter reconstructs traffic, trains T1/T2, builds field profiles, calibrates on validation runs and predicts on independent test runs. |
| T2 and role inference per T1 group | Reuses `opcua_ids.chain_t1_t2.run_chain`. `detection.py` actually checks inferred constant fields and short variable fields; schemas are not just exported and ignored. |
| Additional clients, shared process, reliable labels, TCP reconstruction, separate splits | Three masters and a monitor; real Npcap captures; exact logged request matching; TCP sequence reconstruction; independent training, validation and test sessions. |
| Multi-master Modbus | Masters 1, 2 and 3 write only HR1, HR2 and HR3. HR0 models a tank level affected by all three controls. The monitor reads HR0..HR3 only. Captured requests verify ownership; responses show process changes. |
| Random client attacker and detection evaluation | A recorded random seed chooses one of the three masters. That existing client issues a bounded attack. Per-request and per-window results, false alarms and raw predictions are saved. |



## Files

- `lab.py`: small Modbus/TCP lab server, masters and monitor; OPC UA gateway to
  that same server; operation logging and bounded attack injection.
- `streams.py`: TCP reconstruction, protocol framing and exact event matching.
- `detection.py`: protocol-blind T1/T2 field profiling and timing baseline.
- `behavior.py`: separate protocol-aware comparison detector. It uses known
  Modbus fields and the existing OPC UA decoder. It is not blind inference.
- `evaluate.py`: split checks, label/ownership audit, detector calibration,
  frozen test predictions and metrics.
- `run_lab.py`: one-command capture and evaluation orchestration.
- `test_pipeline.py`: reconstruction, label, detector and evaluation tests.


## Run on Windows

Use Python 3.12, Wireshark/dumpcap and Npcap's loopback adapter. The tested versions
are recorded in the capture directory's `environment.txt`.

From the repository root:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r integrated_ids/requirements.txt
.venv/Scripts/python.exe -m unittest paola_t1.test_clustering opcua_ids.test_chain_t1_t2 integrated_ids.test_pipeline -v
.venv/Scripts/python.exe -m integrated_ids.run_lab --out integration_results/my_new_run --capture-seconds 10 --cycles 120 --seed 6400
```

The output directory must be new. Use `--dumpcap` and `--interface` if the local installation differs. The loopback filter records only the ephemeral port used by this lab session. Each session stops, closes its sockets, and ends capture. Server binding fails rather than taking over an occupied port.

To evaluate the supplied captures again without opening any network sockets:

```powershell
.venv/Scripts/python.exe -m integrated_ids.evaluate integration_results/multimaster_extended_20261118/manifest.json
```

`run_lab.py` already invokes that evaluation after capture. Separate invocation is
also supported; it does not retrain on validation or test records.

## Experiment design

For each protocol the extended run has two normal training captures, two normal
validation captures, two normal test captures and four mixed normal/attack test
captures. Each has new connections and a reset shared process. Traffic duration
and polling delay vary using a fixed seed. Masters maintain separate connections; the read-only monitor operates concurrently. The OPC UA clients communicate through a live gateway which mirrors the tank and forwards writes to Modbus HR1..HR3.

The four Modbus attacks are an unsupported function, a value jump, a write without a prior read on a fresh connection of the selected master, and 60 rapid reads. OPC UA substitutes invalid-node access for the unsupported function. Normal clients continue while the selected master performs its attack. The chosen master, seed, ownership, capture hashes and split membership are in `manifest.json`.

These controlled new scenarios do not re-run every historical attack in the
repository (for example session flood, replay or malformed declared lengths).
They test the multi-client extension and the four documented attack behaviors.

## What "verified labels" means

Each outgoing request is logged at the sender with timestamp, full source and
destination IP/port, client identity, exact bytes, SHA256 and normal/attack label. Modbus transaction IDs and OPC UA request bytes distinguish consecutive requests. Capture records are matched one-to-one against that evidence, with a two-second timestamp tolerance. The match does not assume the busiest port is normal. Unmatched or ambiguous traffic is never silently labeled normal. Final evaluation refuses incomplete matching, damaged streams, duplicate captures or attacks in training/validation. Controlled sender logs are the ground truth for this lab;they are not an independent oracle for arbitrary third-party traffic.

The extended run matched **12,622 requests/frames**, with no unmatched log events, no ambiguous labels and no quarantined request connections. Ownership checks found no normal writes outside each master's register, and no monitor writes.

## Reconstruction and inference boundaries

TCP reconstruction groups by connection and SYN generation, orders sequence
numbers, removes identical retransmissions/overlap, handles sequence wrap and
joins split payloads. Gaps and conflicting overlaps quarantine a connection.
Tests also cover multiple application frames in one TCP payload. Modbus lab
clients deliberately split some requests across writes to exercise reassembly.

Framing uses known MBAP or UA TCP length headers. **Framing is protocol-aware;
T1/T2 field inference is blind.** T1/T2 receive only raw framed bytes. Ports,
ground-truth labels, node IDs and ownership are not learner inputs.

OPC UA units are UA TCP chunks. Reconstructing multi-chunk UASC service bodies is not implemented. No continuation chunks occurred in this experiment. Encrypted OPC UA decoding is not supported. Connections captured midstream are reported; arbitrary missing headers and malformed framing cannot be recovered reliably.

The existing T2 threshold and merge/role heuristics are reused. Numeric field
ranges use a big-endian heuristic only for spans up to eight bytes. Counter fields and longer variable fields are not range-checked. Constant fields are checked at any length. This is not a semantic OPC UA parser, and true boundary accuracy has not been validated. Adjacent constant fields can still be merged incorrectly.

## Frozen calibration and measured results

Training learns T1 groups, T2 fields and normal field values. Independent normal validation runs select the 95th-percentile alarm thresholds. Test data are not used to select these thresholds. The model and profiles remain frozen for test prediction; connection history for the protocol-aware baseline resets per run.

The initial 16 very short captures in `multimaster_20261118` were engineering
smoke tests. Their counts made frequency results uninformative. The extended
20-capture experiment uses more cycles, timing variation and additional normal
validation/test sessions. Both rounds are retained; they are not pooled.

Extended run sample counts:

| Protocol | Training | Validation | Test normal | Test attack |
| --- | ---: | ---: | ---: | ---: |
| Modbus | 1,132 | 1,184 | 3,754 | 63 |
| OPC UA | 1,204 | 1,255 | 3,967 | 63 |

Per-request/frame results for the hybrid (inferred structure OR rate OR
protocol-aware behavior):

| Protocol | Detected attack requests | Recall | False alarms / normal requests | False-positive rate |
| --- | ---: | ---: | ---: | ---: |
| Modbus | 53 / 63 | 84.13% | 414 / 3,754 | 11.03% |
| OPC UA | 55 / 63 | 87.30% | 1,274 / 3,967 | 32.11% |

These results are **not** blind-inference accuracy. The protocol-aware baseline
detected the three isolated semantic/structural attack requests per protocol.
Most remaining detections came from rate changes during the 60-request flood.
The micro-average is dominated by that one flood; there is only one instance of
each other attack per protocol. Precision is low (11.35% Modbus, 4.14% OPC UA).

The blind structural method by itself generated too many normal validation alerts. Its binary threshold became 1, disabling calibrated structural alerts. Thus it added no detections to the calibrated hybrid in this run. Uncalibrated structural results are preserved as diagnostics: normal false-positive rates were 14.22% for Modbus and 13.01% for OPC UA. Do not present this as proof that blind inference improves detection.

Statistics also have **separate** 1-second-window metrics, because a burst can
raise a rate alarm on normal requests immediately after the attack. Each window
is positive only if it contains an explicitly logged attack request. In the
extended run the hybrid alerted on four of four attack-positive windows for each protocol, with 2/23 false-positive normal windows for Modbus and 4/19 for OPC UA. Those very small window counts do not establish reliable 100% attack detection. Window results must not be mixed with per-request results.

Files under `integration_results/multimaster_extended_20261118` include raw PCAPNG, sender logs, capture logs, manifest, dependency versions, inferred profiles, per-request predictions and `evaluation.json`. `integration_results/pipeline_tests.txt` records the automated tests. This experiment establishes functionality and reproducibility, while showing that false alarms and cross-session generalization need more work before deployment or strong research claims.
