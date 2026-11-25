# CS5390Project

Add randomized multi-attack lab and fix multi-master evaluation gaps

- lab.py / run_lab.py: extend the multi-master lab to all 7 Modbus
  attacks (illegal_func, value_jump, write_no_read, read_flood,
  out_of_range, replay) and all 5 OPC UA attacks (invalid_node,
  value_jump, write_no_read, read_flood, session_flood), instead of
  one fixed attack per protocol.

- lab.py: randomize attack timing (attack cycle chosen within a
  30-70% window instead of a fixed point) and attack-specific
  parameters (jump magnitude, flood burst size, bogus function code,
  out-of-range quantity), instead of one fixed template per attack,
  per reviewer feedback on what a more unpredictable attacker looks
  like.

- run_lab.py: add --seeds-per-attack, running several independent
  randomized instances per attack type instead of one, so recall per
  attack type is a real fraction (n>1) instead of a single pass/fail.

- behavior.py: add per-node ownership tracking (which master is
  allowed to write which register/node), catching a well-formed,
  in-range write to the wrong owner's register, which no field-level
  check can see.

- detection.py: graded (count-of-violations) scoring instead of
  binary, and min_samples=4 for clustering with 3 masters splitting
  traffic three ways; both were pushing the calibrated threshold to
  effectively disable the blind detector on clean multi-master
  validation traffic.

- generic_pipeline.py: fix counter-field misclassification under
  multi-master traffic. T1 clustering pools messages from independent
  TCP connections; interleaving their independent per-connection
  counters (e.g. transaction ID) by arrival order destroyed
  monotonicity, mislabeling the field "variable" and cascading into
  100% false positives. Counter check is now per-connection and
  width-aware instead of pooled and hardcoded to 16 bits.

- streams.py: attach_labels() resolves same-connection duplicate
  payloads (repeated reads, floods, replay) in send order instead of
  marking them ambiguous. TCP guarantees order on one connection, so
  this recovers correct labels instead of discarding both sides.

- run_lab.py: stop dumpcap right after traffic generation finishes
  (plus a short grace period), instead of racing a fixed capture
  duration against randomized, variable-length traffic generation.
  Fixes trailing OPC UA events being logged after the capture had
  already stopped.

- run_lab.py: remove bad_length from the multi-master attack set.
  Lying about the MBAP length field breaks the strict one-frame-per-
  send reconstruction assumption; documented as a structural scope
  boundary rather than patched around per-run.

- infer_roles.py / chain_t1_t2.py: port the per-connection,
  width-aware counter fix (above) into the blind T1/T2 path used by
  integrated_ids, which was still calling the old pooled check and
  getting disabled by calibration the same way generic_pipeline.py
  originally was.

- test_pipeline.py: updated the ambiguous-duplicate test to assert
  the new send-order resolution behavior; added a separate test for
  the still-ambiguous out-of-tolerance case.
