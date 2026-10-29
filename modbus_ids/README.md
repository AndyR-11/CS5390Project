# Modbus IDS Starter

A minimal, runnable starting point for the structure-based vs.
statistics-only detector comparison.

## Run it on synthetic traffic (no lab needed)

    python3 run_demo.py

You should see a learned profile printed, then two results tables
showing detection rate per attack type and the false positive rate on
clean traffic.

## Run it on REAL pcaps from your lab

    python3 run_demo_real.py normal_traffic.pcapng attack_traffic.pcapng

- `normal_traffic.pcapng`: a capture with ONLY the client talking to
  the server (no attacker.py running).
- `attack_traffic.pcapng`: a capture with the client running AND
  attacker.py --attack all running at the same time.
- Assumes you captured on port 502 (set MODBUS_PORT at the top of
  run_demo_real.py if you used a different port).
- **Known limitation:** without per-attack timestamps, every message
  in attack_traffic.pcapng gets the generic label "attack:mixed" --
  normal traffic captured in that same file will show up as a "missed
  attack" in the results table, which is misleading. For a proper
  per-attack-type breakdown, capture each attack separately:

      python3 attacker.py --host 127.0.0.1 --port 502 --attack illegal_func
      (capture this as illegal_func.pcapng, then repeat per attack type)

  and run pcap_loader.load_pcap() on each file with its own label
  (e.g. "attack:illegal_func"), concatenating the results before
  calling evaluate.evaluate_struct(). See pcap_loader.py's docstring
  for the label_messages_by_log() alternative if you have one mixed
  capture plus rough start/end timestamps for each attack.

## Files

- schema.py          - field layout (PLACEHOLDER: replace with your
                        own T2 inference output once it's ready)
- parser.py           - turns raw bytes into named fields, using schema.py
- traffic_sim.py      - generates fake normal + attack traffic for testing
- pcap_loader.py      - loads REAL .pcap/.pcapng captures into the same
                        message format traffic_sim.py produces (tested
                        against real scapy-written captures, including
                        the loopback case)
- profile.py          - learns "what's normal" from training traffic
- detector_struct.py  - the structure-aware detector
- detector_stats.py   - the statistics-only baseline
- evaluate.py         - scores both detectors against ground truth
- run_demo.py         - runs everything end to end on SYNTHETIC traffic
- run_demo_real.py    - runs everything end to end on REAL pcaps

## Swapping in your real inference

Once your T2 (field boundary/role inference) code works, replace
DEFAULT_SCHEMA in schema.py with whatever it outputs, ideally loaded
from a JSON file your inference script writes. The parser, profile
builder, and detector don't need to change -- they just read whatever
schema they're given.

## Known limitation of the detectors (be honest about this in your report)

The structure detector currently misses read floods (each message is
individually valid) and only partially catches replays. This is
expected and is a good talking point: it's exactly why the two
detectors are complementary rather than one replacing the other.
