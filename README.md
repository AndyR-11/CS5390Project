# CS5390 Project: blind protocol inference and anomaly detection for Modbus/TCP and OPC UA

A small cyber-physical lab (a simulated tank PLC reachable over Modbus/TCP and, through a gateway, over unencrypted OPC UA)
plus the tooling around it: attack generators, real packet captures, a **blind** pipeline that infers message structure from
raw bytes alone, and three detectors (structure, statistics, behavioral) that are scored against labeled attacks.

> Branch note: this README describes the `opc` branch. `paola_t1/` (the T1 message-type clustering) lives on `main`, and the
> T2 / role-inference scripts (`infer_boundaries.py`, `infer_merge.py`, `infer_roles.py`) are kept outside the repo tree;
> see section 4 for where they are expected.

## 1. Repository layout

```
CS5390Project/
├── README.md                          This file: layout, setup, and every run command with what it does.
├── .gitignore                         Ignores __pycache__/, *.pyc, .venv/ and .DS_Store.
├── normal_traffic_small.pcapng        A short clean Modbus capture (about 7 minutes, port 502) for quick smoke tests.
├── scratch_traffic.pcapng             A Modbus capture from early lab experiments that also contains a few function-43 requests, so it is not clean.
│
├── modbus_lab_setup/                  The Modbus side of the lab: simulated PLC, clients, attacker.
│   ├── modbus_lab/
│   │   ├── modbus_server.py           Simulated PLC: a Modbus/TCP server holding the tank-level and setpoint registers.
│   │   ├── modbus_client.py           Normal HMI-style client that polls registers and occasionally writes the setpoint.
│   │   ├── multi_client_lab.py        Starts a random number of normal clients, makes one of them the attacker, and writes a ground-truth JSON.
│   │   └── attacker.py                Runs the 7 Modbus attacks (illegal_func, bad_length, out_of_range, replay, read_flood, write_no_read, value_jump).
│   └── *.pcapng                       Copies of the Modbus captures (clean + one per attack), byte-identical to those in modbus_ids/.
│
├── modbus_ids/                        The Modbus detection pipeline (hand-written schema, three detectors, scoring).
│   ├── schema.py                      The hand-written field layout (DEFAULT_SCHEMA) of a Modbus/TCP message; inferred schemas are drop-in replacements.
│   ├── parser.py                      Turns one raw Modbus message into a dict of field values using any schema of that shape.
│   ├── pcap_loader.py                 Loads a .pcap/.pcapng into a message list, including auto-labeling of "mixed" captures by connection.
│   ├── profile.py                     Learns what normal looks like (allowed functions, address ranges, rate, size, gaps) from clean traffic.
│   ├── detector_struct.py             Flags a single message that violates the learned structure (e.g. unseen function code, wrong length, address out of range).
│   ├── detector_stats.py              Statistics-only baseline that flags time windows whose rate, size or gap is far from normal.
│   ├── detector_behavioral.py         Stateful detector for sequence attacks: write_no_read and value_jump.
│   ├── evaluate.py                    Scores detector output against ground-truth labels (per message or per window) and prints the report.
│   ├── traffic_sim.py                 Generates synthetic Modbus-like traffic with injected attacks, for use before real captures exist.
│   ├── run_demo.py                    Runs the whole pipeline end to end on synthetic traffic.
│   ├── run_demo_real.py               Older single-file real-pcap runner, superseded by run_demo_real_multi.py.
│   ├── run_demo_real_multi.py         Runs all three detectors on real captures: one clean pcap plus one pcap per attack.
│   ├── label_by_truth.py              Labels a multi-client capture from the ground-truth JSON written by multi_client_lab.py.
│   └── *.pcapng                       The Modbus captures: normal_traffic plus one per attack (captured on port 502).
│
├── opcua_lab_setup/                   The OPC UA side of the lab (Python asyncua, SecurityPolicy None).
│   ├── opcua_gateway.py               Modbus client plus OPC UA server: mirrors the PLC registers as TankLevel / Setpoint nodes.
│   ├── opcua_client.py                Normal OPC UA traffic generator: polls both nodes and occasionally nudges the setpoint.
│   └── opcua_attacker.py              Runs the 5 OPC UA attacks (invalid_node, write_no_read, value_jump, read_flood, session_flood).
│
├── opcua_ids/                         Everything for analysing OPC UA traffic; see opcua_ids/README.txt for details.
│   │  -- blind inference (no protocol knowledge) --
│   ├── pcap_loader_generic.py         Loads TCP payloads on a given server port, one payload per message, with no protocol parsing.
│   ├── infer_structure.py             Infers message clusters, byte-variability segments and length fields from raw bytes alone.
│   ├── run_opc_inference.py           Runs the inference on a normal capture and writes the inferred JSON schema.
│   ├── opcua_inferred_schema.json     The schema that run_opc_inference.py produced from the normal capture.
│   ├── evaluate_opc_basic.py          First-version structure/rate evaluation of attack captures using the inferred schema.
│   ├── run_t1_t2_roles.py             Chains T1 clustering, T2 field boundaries, merge and role labeling on an OPC UA capture.
│   ├── eval_t2_boundaries.py          Scores the inferred field boundaries against a hand-decoded OPC UA ReadRequest layout.
│   ├── sweep_t2_params.py             Sweeps the T2 thresholds to show no setting beats the defaults (a structural limit).
│   │  -- protocol-aware evaluation (decodes OPC UA) --
│   ├── opc_decode.py                  Decodes one UA-TCP request into message type, service, node ids and written values.
│   ├── opc_loader.py                  Loads a capture into decoded messages, reassembling TCP streams and dropping retransmissions.
│   ├── opc_detectors.py               Profiles plus the structure, statistics and behavioral detectors for OPC UA.
│   ├── opc_labels.py                  Ground-truth labels from what opcua_attacker.py is scripted to do, plus splice() to overlay an attack on normal traffic.
│   ├── run_opc_eval.py                The OPC UA evaluation driver; scores the three detectors with modbus_ids/evaluate.py.
│   ├── test_opc_pipeline.py           23 unit and regression tests for the decoder, loader, detectors and labeling.
│   └── README.txt                     Detailed notes on the blind pipeline and the evaluation pipeline.
│
└── pcaps/opcua/                       Real OPC UA captures: normal plus one per attack.
    ├── opc_<name>.pcapng              Full capture, including the gateway's Modbus backend traffic on port 5020.
    └── opc_<name>_only.pcapng         The same capture filtered to OPC UA only (port 4840); use these for the analysis.
```

## 2. Setup

```bash
python3 -m pip install scapy pymodbus asyncua      # tested with Python 3.12, scapy 2.8, pymodbus 3.16, asyncua 2.1
sudo apt-get install tcpdump                       # only needed to capture your own traffic
```

## 3. Modbus: lab, captures and detection

**Run the lab** (each in its own terminal; the server must be up first):

```bash
cd modbus_lab_setup/modbus_lab
python3 modbus_server.py --host 127.0.0.1 --port 5020     # start the simulated PLC
python3 modbus_client.py --duration 60                     # one normal client polling the PLC for 60 s
python3 attacker.py --host 127.0.0.1 --port 5020 --attack write_no_read   # fire one attack (or --attack all)
```

**Random multi-client scenario** (start the capture first, in another terminal):

```bash
sudo tcpdump -i lo -w run1.pcap "tcp port 5020"            # capture the PLC traffic
python3 multi_client_lab.py --duration 60 --seed 1 --out-prefix run1
# starts 2-6 normal clients (--min-clients / --max-clients), makes one of them the attacker,
# fires one random attack (or --attack value_jump) at a random moment, and writes run1_truth.json
cd ../../modbus_ids
python3 label_by_truth.py ../modbus_lab_setup/modbus_lab/run1.pcap ../modbus_lab_setup/modbus_lab/run1_truth.json
# labels each request normal / attack:<name> from the truth file and prints the counts
```

**Run the detectors:**

```bash
cd modbus_ids
python3 run_demo.py                                        # full pipeline on synthetic traffic (no capture needed)
python3 run_demo_real_multi.py normal_traffic.pcapng illegal_func.pcapng bad_length.pcapng \
    out_of_range.pcapng replay.pcapng read_flood.pcapng write_no_read.pcapng value_jump.pcapng
# learns the profile from the clean capture, runs the structure, statistics and behavioral
# detectors on each attack capture, and prints a recall / false-positive report per detector
```

`run_demo_real_multi.py` reads the capture on port `MODBUS_PORT = 502`, which is what the included captures use. Captures
taken against the lab's default port 5020 need that constant changed.

## 4. OPC UA: lab, blind pipeline, and T1/T2 on OPC UA

**Run the lab** (start in this order; the gateway talks to the Modbus server from section 3):

```bash
python3 modbus_lab_setup/modbus_lab/modbus_server.py --host 127.0.0.1 --port 5020   # the PLC behind the gateway
cd opcua_lab_setup
python3 opcua_gateway.py                                    # OPC UA server on :4840 mirroring the PLC registers
python3 opcua_client.py --duration 60                       # normal OPC UA client
python3 opcua_attacker.py --attack read_flood               # one attack: invalid_node | write_no_read | value_jump | read_flood | session_flood
sudo tcpdump -i lo -w opc_run.pcap "tcp port 4840"          # capture the OPC UA side (start it before the client)
```

**Blind inference** (uses only raw bytes and the server port; no OPC UA field names):

```bash
cd opcua_ids
python3 run_opc_inference.py ../pcaps/opcua/opc_normal_only.pcapng --port 4840 --out opcua_inferred_schema.json
# clusters the normal messages by prefix, segments them by byte variability, and writes the inferred schema

python3 evaluate_opc_basic.py opcua_inferred_schema.json \
    ../pcaps/opcua/opc_normal_only.pcapng ../pcaps/opcua/opc_invalid_node_only.pcapng \
    ../pcaps/opcua/opc_write_no_read_only.pcapng ../pcaps/opcua/opc_value_jump_only.pcapng \
    ../pcaps/opcua/opc_read_flood_only.pcapng ../pcaps/opcua/opc_session_flood_only.pcapng --port 4840
# applies the inferred schema to each attack capture and reports structure alerts and request rate
```

**T1 / T2 / roles on OPC UA** (needs `clustering.py` from `main:paola_t1/` and the three `infer_*.py` scripts on `PYTHONPATH`):

```bash
export PYTHONPATH=../paola_t1:/path/to/t2_scripts
python3 run_t1_t2_roles.py ../pcaps/opcua/opc_normal_only.pcapng      # T1 clusters, then T2 fields, merge and roles per cluster
python3 eval_t2_boundaries.py                                         # boundary precision / recall / F1 against the decoded layout
python3 sweep_t2_params.py                                            # parameter sweep: confirms the defaults are already best
```

## 5. OPC UA evaluation (decoder plus three detectors)

```bash
cd opcua_ids
python3 run_opc_eval.py --train ../pcaps/opcua/opc_normal_only.pcapng \
    --heldout <a second, separate clean capture> \
    ../pcaps/opcua/opc_invalid_node_only.pcapng ../pcaps/opcua/opc_write_no_read_only.pcapng \
    ../pcaps/opcua/opc_value_jump_only.pcapng ../pcaps/opcua/opc_read_flood_only.pcapng \
    ../pcaps/opcua/opc_session_flood_only.pcapng
# learns profiles from --train, measures false positives on --heldout, scores each detector on every
# attack, and prints a per-detector report, a recall matrix and why each alert fired (add --json out.json to save)

python3 -m unittest test_opc_pipeline -v                    # 23 tests: decoder, reassembly, detectors, labels, regressions
```

Current result on the included captures (false-positive rate 0.000 for all three, measured on a second clean capture
taken in the lab described above):

| Attack | Structure | Statistics | Behavioral |
|---|---|---|---|
| invalid_node | 1.00 | 0.00 | 0.00 |
| write_no_read | 0.00 | 0.00 | 1.00 |
| value_jump | 0.00 | 0.00 | 1.00 |
| read_flood | 0.00 | 1.00 | 0.00 |
| session_flood | 0.00 | 1.00 | 0.00 |

Structure and behavioral recall is per message, statistics recall is per 5 s window, and each attack contributes only a
handful of messages or windows, so treat these as a sanity check, not a benchmark.

## 6. Things worth knowing

- **Use a separate `--heldout` capture.** With a single capture, a 70/30 time split puts session teardown only in the test half, and every detector false-alarms on it (5.8% in our run).
- **Attacks are spliced into normal traffic for scoring.** The OPC UA attack captures hold only the attacker's session and last under 0.2 s, so `opc_labels.splice()` overlays them on normal traffic. The statistics detector is fed only the attack's own messages by default; `--stats-splice full-session` shows why (the extra handshake alone trips the rate check).
- **The statistics baseline is fragile around session starts.** A new session's first 5 s window holds about 24 messages (4.8 msg/s) against an alarm limit of about 4.9, so the zero false-positive rate rests on a small margin. Counting only data-plane requests in the rate feature would remove that.
- **`write_no_read` is per connection in the OPC UA detector.** The Modbus detector tracks reads globally, so another client's read can hide an attacker's write, and it flags every write in the included `normal_traffic.pcapng`.
- **The last partial window is dropped** from clean-traffic windows (training and false-positive scoring) so a capture that simply ends can't look like an anomaly.
- **Housekeeping:** `modbus_ids/` and `modbus_lab_setup/` hold identical copies of the 8 Modbus captures (about 3 MB duplicated), and some `__pycache__/*.pyc` files were committed before `.gitignore` covered them (`git rm -r --cached` on them cleans that up).
