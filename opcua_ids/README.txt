OPC UA blind

Purpose
-------
Keep existing Modbus IDS untouched. This folder creates a parallel,
protocol-generic pipeline for your OPC UA captures:

  OPC-only PCAP -> generic TCP payload loader -> blind prefix clustering
  -> byte-variability field segmentation -> inferred JSON schema
  -> basic structure/statistics evaluation

The inference code is intentionally not given OPC UA field names.
It works only from raw bytes and a configured TCP server port.

Files in this folder
--------------------
Blind inference (raw bytes only, no OPC UA knowledge):
  pcap_loader_generic.py     loads TCP payloads on a server port, one payload per message
  infer_structure.py         prefix clustering, byte-variability segments, length-field candidates
  run_opc_inference.py       runs the inference on a normal capture, writes the schema JSON
  opcua_inferred_schema.json the schema produced from opc_normal_only.pcapng
  evaluate_opc_basic.py      first-version structure / request-rate evaluation with that schema
  run_t1_t2_roles.py         chains T1 clustering -> T2 boundaries -> merge -> roles on a capture
  eval_t2_boundaries.py      scores inferred boundaries against a hand-decoded ReadRequest layout
  sweep_t2_params.py         sweeps the T2 thresholds (finding: defaults are already the best)

Protocol-aware evaluation (decodes OPC UA):
  opc_decode.py              one UA-TCP request -> message type, service, node ids, written value
  opc_loader.py              capture -> decoded messages (TCP reassembly, retransmissions dropped)
  opc_detectors.py           profiles + structure / statistics / behavioral detectors
  opc_labels.py              ground-truth labels from the attacker script; splice() helper
  run_opc_eval.py            evaluation driver (scores with ../modbus_ids/evaluate.py)
  test_opc_pipeline.py       23 tests: python3 -m unittest test_opc_pipeline -v

Install
-------
python3 -m pip install scapy

Run inference on NORMAL traffic first
-------------------------------------
python3 run_opc_inference.py \
  ../pcaps/opcua/opc_normal_only.pcapng \
  --port 4840 \
  --out opcua_inferred_schema.json

Then evaluate attack captures
-----------------------------
python3 evaluate_opc_basic.py \
  opcua_inferred_schema.json \
  ../pcaps/opcua/opc_normal_only.pcapng \
  ../pcaps/opcua/opc_invalid_node_only.pcapng \
  ../pcaps/opcua/opc_write_no_read_only.pcapng \
  ../pcaps/opcua/opc_value_jump_only.pcapng \
  ../pcaps/opcua/opc_read_flood_only.pcapng \
  ../pcaps/opcua/opc_session_flood_only.pcapng \
  --port 4840

What this first version can and cannot do
-----------------------------------------
CAN:
- discover repeated message prefixes without protocol field names
- segment constant / low-cardinality / variable byte regions
- find likely length fields by checking 2/4-byte values against raw message length
- flag unseen message clusters and abnormal message lengths
- flag high request-rate captures

CANNOT YET:
- understand OPC UA NodeIds / service semantics
- recognize write_no_read as a semantic sequence violation
- recognize value_jump from decoded OPC UA values

Those semantic detectors are the next phase after the blind structural baseline.

OPC UA evaluation pipeline
--------------------------
Counterpart of ../modbus_ids/run_demo_real_multi.py. Unlike the blind pipeline above it IS
protocol-aware (opc_decode.py reads service type, node ids and written values); it is the
semantic layer the "CANNOT YET" list refers to.

Run (add --json out.json to save the results):
  python3 run_opc_eval.py --train ../pcaps/opcua/opc_normal_only.pcapng \
      --heldout <a second, separate normal capture> \
      ../pcaps/opcua/opc_invalid_node_only.pcapng ../pcaps/opcua/opc_write_no_read_only.pcapng \
      ../pcaps/opcua/opc_value_jump_only.pcapng ../pcaps/opcua/opc_read_flood_only.pcapng \
      ../pcaps/opcua/opc_session_flood_only.pcapng

What it does: learns the three profiles from --train, measures false positives on --heldout,
splices each attack into the held-out normal traffic, scores every detector with the same
evaluate.py the Modbus pipeline uses, and prints reports, a recall matrix and why each alert fired.
Attack file names must look like opc_<attack>_only.pcapng.

Options: --port (default 4840), --splice-at (where in the background the attack lands, 0-1),
         --stats-splice attack-only|full-session (what the statistics detector sees of an attack).

Design notes:
- --heldout matters: with one capture a 70/30 time split puts session teardown only in the
  test half and every detector false-alarms on it (5.8% FPR in our run).
- Attack captures hold only the attacker's own session and last <0.2 s, so each is spliced onto
  the held-out normal traffic (message level) to give the statistics detector real windows.
- The statistics detector sees only the attack's own messages by default. Splicing a whole extra
  session adds ~10 handshake messages to the window, which trips the rate check whether or not
  the attack changes the rate (it makes write_no_read / value_jump look statistically visible).
- The last partial window of every clean capture is dropped (training and false-positive scoring).
- write_no_read is tracked per connection; the Modbus detector tracks reads globally, which
  lets another client's read hide an attacker's write.
- value_jump: an out-of-range value is not remembered as the "last value", so one attack write
  does not make the next legitimate write look like a jump.
- Known limits: segments are consumed in capture order (no out-of-order re-sequencing); the
  statistics rate feature counts handshake messages, so a new session's first window sits close
  to the alarm threshold; each attack contributes only a few messages/windows to the scores.
