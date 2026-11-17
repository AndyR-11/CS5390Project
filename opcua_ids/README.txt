OPC UA IDS

Purpose

This folder provides the OPC UA side of the project and follows the same
general detector organization used by modbus_ids.

The OPC UA lab uses unencrypted OPC UA traffic with SecurityPolicy None
on TCP port 4840.

The detector pipeline includes:

Structure-based detection

Statistics-only detection

Behavioral detection

The normal OPC UA capture is divided chronologically into:

first 70% for training

final 30% for held-out false-positive evaluation

Each attack is stored in a separate OPC-only PCAP capture.
