"""Telemetry adapters (spec sections 42-43).

External telemetry (cloud flow logs, Kubernetes inventories) is normalized
into the same internal models used by passive capture: flows, hosts and
services. Cloud flow logs never contain packet payloads and are always stored
as profile-A equivalent metadata: no evidence sealing is attempted, no packet
rows are fabricated.
"""

from .flowlogs import (
    FLOWLOG_FORMATS,
    FlowlogError,
    detect_format,
    import_flowlogs,
    parse_flowlogs,
)
from .k8s import (
    K8sError,
    correlate_capture,
    import_inventory,
    list_entities,
    normalize_inventory,
)

__all__ = [
    "FLOWLOG_FORMATS",
    "FlowlogError",
    "detect_format",
    "import_flowlogs",
    "parse_flowlogs",
    "K8sError",
    "correlate_capture",
    "import_inventory",
    "list_entities",
    "normalize_inventory",
]
