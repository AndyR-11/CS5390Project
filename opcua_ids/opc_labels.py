"""
Ground-truth labeling for the OPC UA attack captures.

The labels come from what opcua_attacker.py is scripted to do, NOT from any detector:

  invalid_node   the Read of the nonexistent node 'DefinitelyNotARealNode'
  write_no_read  the Write (it never reads Setpoint first)
  value_jump     the Write of 999 (the preceding precheck Read is ordinary-looking)
  read_flood     the 50 back-to-back reads of TankLevel (the last `count` Reads)
  session_flood  every message of the 20 short-lived sessions

The attacker's own session setup/teardown (HEL, OPN, CreateSession, ...) is identical to
what any normal client sends, so it stays labeled "normal".
"""
ATTACKS = ["invalid_node", "write_no_read", "value_jump", "read_flood", "session_flood"]
FLOOD_READS = 50


def attack_name_from_path(path):
    """opc_read_flood_only.pcapng -> read_flood"""
    import os
    stem = os.path.splitext(os.path.basename(path))[0]
    stem = stem[4:] if stem.startswith("opc_") else stem
    stem = stem[:-5] if stem.endswith("_only") else stem
    if stem not in ATTACKS:
        raise ValueError(f"can't tell the attack from {path!r}; expected one of {ATTACKS}")
    return stem


def label_attack_messages(msgs, attack):
    """Mutates and returns msgs, setting label to 'attack:<name>' on the attack messages."""
    tag = "attack:" + attack
    if attack == "session_flood":
        for m in msgs:
            m["label"] = tag
    elif attack == "invalid_node":
        for m in msgs:
            if m["dec"]["service"] == "Read" and b"DefinitelyNotARealNode" in m["raw"]:
                m["label"] = tag
    elif attack in ("write_no_read", "value_jump"):
        for m in msgs:
            if m["dec"]["service"] == "Write":
                m["label"] = tag
    elif attack == "read_flood":
        reads = [m for m in msgs if m["dec"]["service"] == "Read"]
        for m in reads[-FLOOD_READS:]:
            m["label"] = tag
    return msgs


def splice(background, attack_msgs, at_fraction=0.5, conn_offset=10_000):
    """
    Overlay an attack-only capture onto a normal background capture, at message level.

    The attack's messages are shifted in time so its first message lands `at_fraction`
    of the way through the background. Background messages get src='bg', attack-capture
    messages src='atk' (so scoring can tell whose false positives are whose). Returns a
    new chronological list; inputs are not modified.
    """
    t0, t1 = background[0]["ts"], background[-1]["ts"]
    shift = (t0 + at_fraction * (t1 - t0)) - attack_msgs[0]["ts"]
    out = [dict(m, src="bg") for m in background]
    for m in attack_msgs:
        out.append(dict(m, ts=m["ts"] + shift, conn_id=m["conn_id"] + conn_offset, src="atk"))
    out.sort(key=lambda m: m["ts"])
    return out
