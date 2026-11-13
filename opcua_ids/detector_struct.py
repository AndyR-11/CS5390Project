"""
Structure-based OPC UA detector.

Checks one raw OPC UA TCP payload against a structure profile learned
from normal training traffic.

The structure is learned blindly from message prefixes and observed
length ranges. No OPC UA field names are required for this detector.
"""


def struct_detect(raw, profile):
    prefix_width = profile.prefix_width

    key = (
        raw[:prefix_width].hex()
        if len(raw) >= prefix_width
        else raw.hex()
    )

    cluster = profile.cluster_map.get(key)

    if cluster is None:
        return "unseen_message_cluster"

    if not (
        cluster["min_len"]
        <= len(raw)
        <= cluster["max_len"]
    ):
        return "unexpected_length"

    return None
