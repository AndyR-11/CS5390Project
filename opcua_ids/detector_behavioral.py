from collections import defaultdict
from opcua_decode import decode_messages


READ_WINDOW_SEC = 5.0


class OPCBehavioralProfile:
    def __init__(self):
        self.known_nodes = set()

        # node -> maximum allowed normal write step
        self.max_write_step = {}

        # node -> final normal training write
        self.last_write_value = {}

        self.read_before_write_sec = READ_WINDOW_SEC

    def __repr__(self):
        return (
            "OPCBehavioralProfile("
            f"known_nodes={len(self.known_nodes)}, "
            f"max_write_step={self.max_write_step})"
        )


def _numeric(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def build_behavioral_profile(
    normal_messages,
    read_window_sec=READ_WINDOW_SEC
):
    profile = OPCBehavioralProfile()
    profile.read_before_write_sec = read_window_sec

    events = decode_messages(normal_messages)

    writes_by_node = defaultdict(list)

    for event in events:
        if event["kind"] == "read":
            for node in event["nodes"]:
                profile.known_nodes.add(node)

        elif event["kind"] == "write":
            for write in event["writes"]:
                node = write["node"]
                value = write["value"]

                profile.known_nodes.add(node)

                if _numeric(value):
                    writes_by_node[node].append(value)

    for node, values in writes_by_node.items():
        steps = [
            abs(values[i] - values[i - 1])
            for i in range(1, len(values))
        ]

        if steps:
            # Same idea used by the Modbus behavioral detector:
            # learned maximum normal step + 50% margin.
            profile.max_write_step[node] = max(
                1,
                int(max(steps) * 1.5)
            )
        else:
            profile.max_write_step[node] = 50

        profile.last_write_value[node] = values[-1]

    return profile


def behavioral_detect(messages, profile):
    """
    Detect three OPC behavioral/semantic anomalies:

      1. invalid_node
         A Read/Write references a node never observed in normal traffic.

      2. write_no_read
         A node is written without a recent Read of the same node.

      3. value_jump
         A numeric write changes farther than the normal learned limit.

    Returns a list of dictionaries:
      {
        "reason": "...",
        "node": "...",
        ...
      }
    """
    events = decode_messages(messages)

    alerts = []

    last_read_ts = {}

    # Seed values from normal training, but NOT read timestamps.
    # Attack pcaps are separate captures with unrelated timestamps.
    last_write_value = dict(profile.last_write_value)

    for event in events:
        ts = event["ts"]

        if event["kind"] == "read":
            for node in event["nodes"]:

                if node not in profile.known_nodes:
                    alerts.append({
                        "reason": "invalid_node",
                        "node": node,
                        "ts": ts,
                    })

                last_read_ts[node] = ts

        elif event["kind"] == "write":
            for write in event["writes"]:
                node = write["node"]
                value = write["value"]

                if node not in profile.known_nodes:
                    alerts.append({
                        "reason": "invalid_node",
                        "node": node,
                        "ts": ts,
                    })
                    continue

                recent_read = last_read_ts.get(node)

                if (
                    recent_read is None
                    or ts is None
                    or (ts - recent_read) > profile.read_before_write_sec
                ):
                    alerts.append({
                        "reason": "write_no_read",
                        "node": node,
                        "value": value,
                        "ts": ts,
                    })

                elif (
                    _numeric(value)
                    and node in last_write_value
                    and node in profile.max_write_step
                ):
                    step = abs(
                        value - last_write_value[node]
                    )

                    if step > profile.max_write_step[node]:
                        alerts.append({
                            "reason": "value_jump",
                            "node": node,
                            "old_value": last_write_value[node],
                            "new_value": value,
                            "step": step,
                            "threshold": profile.max_write_step[node],
                            "ts": ts,
                        })

                if _numeric(value):
                    last_write_value[node] = value

    return alerts
