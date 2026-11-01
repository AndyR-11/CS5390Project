OPC UA blind PRE starter

Purpose
-------
Keep existing Modbus IDS untouched. This folder creates a parallel,
protocol-generic pipeline for your OPC UA captures:

  OPC-only PCAP -> generic TCP payload loader -> blind prefix clustering
  -> byte-variability field segmentation -> inferred JSON schema
  -> basic structure/statistics evaluation

The inference code is intentionally not given OPC UA field names.
It works only from raw bytes and a configured TCP server port.

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
