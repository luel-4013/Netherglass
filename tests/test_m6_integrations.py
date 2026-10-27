"""M6 tests: tunnels, cloud flow-log adapters, Kubernetes inventory."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netherglass.analysis import protocols
from netherglass.analysis import rules as rules_mod
from netherglass.api.app import create_app
from netherglass.config import AppConfig
from netherglass.ingest import flowlogs as flowlogs_mod
from netherglass.ingest import k8s as k8s_mod
from netherglass.security.audit import list_events
from netherglass.security.auth import create_user
from netherglass.store import analysis as analysis_store
from netherglass.store import packets as packets_store
from netherglass.store.db import Database

CAPTURE_ID = "cap-20261019-m6-0001"

AWS_LOG = """\
version account-id interface-id srcaddr dstaddr srcport dstport protocol \\
packets bytes start end action log-status
2 123456789010 eni-abc 172.31.16.139 172.31.16.21 20641 22 6 20 4249 \
1418530010 1418530070 ACCEPT OK
2 123456789010 eni-abc 172.31.9.69 172.31.16.21 49761 3389 6 20 4249 \
1418530010 1418530070 REJECT OK
2 123456789010 eni-abc 172.31.9.69 8.8.8.8 5353 53 17 10 1200 \
1418530015 1418530075 ACCEPT OK
"""

AZURE_LOG = json.dumps(
    {
        "records": [
            {
                "time": "2026-10-19T00:00:00Z",
                "properties": {
                    "flows": [
                        {
                            "rule": "DefaultRule_AllowVnetOutBound",
                            "flows": [
                                {
                                    "mac": "001122334455",
                                    "flowTuples": [
                                        "1700000000,10.1.0.4,10.2.0.9,58930,443,T,O,A,C,0",
                                        "1700000001,10.1.0.4,10.2.0.9,58931,3389,T,O,D,C,0",
                                    ],
                                }
                            ],
                        }
                    ]
                },
            }
        ]
    }
)

GCP_LOG = json.dumps(
    {
        "entries": [
            {
                "connection": {
                    "src_ip": "10.10.0.2",
                    "dest_ip": "10.20.0.7",
                    "src_port": 35254,
                    "dest_port": 3306,
                    "protocol": 6,
                },
                "start_time": "2026-10-19T01:00:00Z",
                "end_time": "2026-10-19T01:05:00Z",
                "bytes_sent": 4096,
                "packets_sent": 32,
                "reporter": "SRC",
            }
        ]
    }
)

GENERIC_CSV = """\
ts,src,dst,sport,dport,proto,packets,bytes,action
1700000100,192.168.1.10,93.184.216.34,51000,443,tcp,40,12000,ALLOW
1700000101,192.168.1.10,203.0.113.9,51001,22,tcp,12,800,DENY
"""


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "netherglass.db")
    database.migrate()
    with database.connect() as conn:
        packets_store.create_capture(
            conn,
            capture_id=CAPTURE_ID,
            created_at="2026-10-19T00:00:00+00:00",
            interface="lo",
            profile="C",
            source="import",
            bpf=None,
        )
    return database


def test_detect_tunnel_variants() -> None:
    assert protocols.detect_tunnel(
        {"app_proto": "gre", "proto": "gre"}
    ) == {"protocol": "gre", "state": "DATA", "inner_visible": 1}
    assert protocols.detect_tunnel(
        {"proto": "udp", "dport": 51820, "sport": 40000}
    )["protocol"] == "wireguard"
    assert protocols.detect_tunnel(
        {"proto": "udp", "dport": 500, "sport": 40000}
    )["state"] == "HANDSHAKE"
    assert protocols.detect_tunnel(
        {"proto": "esp", "sport": None, "dport": None}
    )["protocol"] == "ipsec-esp"
    assert protocols.detect_tunnel(
        {"proto": "udp", "dport": 4789, "sport": 40000}
    ) == {"protocol": "vxlan", "state": "DATA", "inner_visible": 1}
    assert protocols.detect_tunnel({"proto": "tcp", "dport": 443}) is None
    assert protocols.detect_tunnel(
        {"proto": "udp", "dport": 1194, "sport": 40000}
    )["protocol"] == "openvpn"
    assert protocols.detect_tunnel(
        {"proto": "udp", "dport": 40000, "sport": 40000},
        layers=["eth", "ip", "ipip", "ip", "icmp"],
    )["protocol"] == "ip-in-ip"


def test_record_batch_creates_tunnels(db: Database) -> None:
    packet = {
        "capture_id": CAPTURE_ID,
        "num": 1,
        "ts": 1700000000.0,
        "src": "10.0.0.5",
        "dst": "10.0.0.9",
        "sport": 40000,
        "dport": 4789,
        "proto": "udp",
        "app_proto": "vxlan",
        "length": 300,
        "tunnel": {"protocol": "vxlan", "state": "DATA", "inner_visible": 1},
    }
    with db.connect() as conn:
        analysis_store.record_batch(conn, CAPTURE_ID, [packet])
        analysis_store.record_batch(conn, CAPTURE_ID, [packet])
        tunnels = analysis_store.list_tunnels(conn, CAPTURE_ID)
    assert len(tunnels) == 1
    assert tunnels[0]["tunnel_proto"] == "vxlan"
    assert tunnels[0]["packets"] == 2
    assert tunnels[0]["bytes"] == 600
    assert tunnels[0]["state"] == "DATA"
    assert tunnels[0]["inner_visible"] == 1
    assert tunnels[0]["duration"] == 0.0


def test_unencrypted_tunnel_rule(db: Database) -> None:
    gre = {
        "capture_id": CAPTURE_ID,
        "num": 1,
        "ts": 1700000000.0,
        "src": "10.0.0.5",
        "dst": "10.0.0.9",
        "sport": None,
        "dport": None,
        "proto": "gre",
        "app_proto": "gre",
        "length": 500,
        "tunnel": {"protocol": "gre", "state": "DATA", "inner_visible": 1},
    }
    esp = {
        "capture_id": CAPTURE_ID,
        "num": 2,
        "ts": 1700000001.0,
        "src": "10.0.0.9",
        "dst": "10.0.0.5",
        "sport": None,
        "dport": None,
        "proto": "esp",
        "app_proto": "esp",
        "length": 600,
        "tunnel": {"protocol": "ipsec-esp", "state": "DATA", "inner_visible": 0},
    }
    with db.connect() as conn:
        analysis_store.record_batch(conn, CAPTURE_ID, [gre, esp])
        count = rules_mod.run_and_store(conn, CAPTURE_ID, data_dir=None)
        findings = conn.execute(
            "SELECT rule_id, severity, confidence FROM findings WHERE capture_id = ?",
            (CAPTURE_ID,),
        ).fetchall()
    assert count >= 1
    by_rule = {row["rule_id"]: row for row in findings}
    assert "unencrypted_tunnel" in by_rule
    assert by_rule["unencrypted_tunnel"]["severity"] == "MEDIUM"
    assert by_rule["unencrypted_tunnel"]["confidence"] == "OBSERVED"


def test_flowlog_parsers() -> None:
    aws_rows = flowlogs_mod.parse_flowlogs(AWS_LOG, "aws")
    assert len(aws_rows) == 3
    assert aws_rows[0]["src"] == "172.31.16.139"
    assert aws_rows[0]["proto"] == "tcp"
    assert aws_rows[0]["dport"] == 22
    assert aws_rows[2]["proto"] == "udp"

    azure_rows = flowlogs_mod.parse_flowlogs(AZURE_LOG, "azure")
    assert len(azure_rows) == 2
    assert azure_rows[0]["dst"] == "10.2.0.9"
    assert azure_rows[0]["proto"] == "tcp"

    gcp_rows = flowlogs_mod.parse_flowlogs(GCP_LOG, "gcp")
    assert len(gcp_rows) == 1
    assert gcp_rows[0]["packets"] == 32
    assert gcp_rows[0]["bytes"] == 4096
    assert gcp_rows[0]["first_ts"] == 1792371600.0

    csv_rows = flowlogs_mod.parse_flowlogs(GENERIC_CSV, "generic-csv")
    assert len(csv_rows) == 2
    assert csv_rows[1]["action"] == "DENY"


def test_detect_format(tmp_path: Path) -> None:
    aws_path = tmp_path / "vpc.log"
    aws_path.write_text(AWS_LOG)
    assert flowlogs_mod.detect_format(aws_path) == "aws"
    azure_path = tmp_path / "nsg.json"
    azure_path.write_text(AZURE_LOG)
    assert flowlogs_mod.detect_format(azure_path) == "azure"
    gcp_path = tmp_path / "flow.json"
    gcp_path.write_text(GCP_LOG)
    assert flowlogs_mod.detect_format(gcp_path) == "gcp"
    csv_path = tmp_path / "flows.csv"
    csv_path.write_text(GENERIC_CSV)
    assert flowlogs_mod.detect_format(csv_path) == "generic-csv"


def test_import_flowlogs_creates_capture(db: Database, tmp_path: Path) -> None:
    path = tmp_path / "vpc.log"
    path.write_text(AWS_LOG)
    result = flowlogs_mod.import_flowlogs(db, path, actor="analyst", label="prod-vpc")
    assert result["format"] == "aws"
    assert result["records"] == 3
    capture_id = result["capture_id"]
    with db.connect() as conn:
        capture = packets_store.get_capture(conn, capture_id)
        flows = packets_store.list_flows(conn, capture_id)
        hosts = analysis_store.list_hosts(conn, capture_id)
        events = list_events(conn)
    assert capture["source"] == "cloud-flowlog"
    assert capture["status"] == "ready"
    assert capture["profile"] == "A"
    assert capture["packets_captured"] == 50
    assert len(flows) == 3
    assert {flow["proto"] for flow in flows} == {"tcp", "udp"}
    assert any(host["ip"] == "8.8.8.8" for host in hosts)
    assert any(event["action"] == "FLOWLOG_IMPORTED" for event in events)


def test_import_flowlogs_rejects_empty(db: Database, tmp_path: Path) -> None:
    path = tmp_path / "empty.log"
    path.write_text("nothing here\n")
    with pytest.raises(flowlogs_mod.FlowlogError):
        flowlogs_mod.import_flowlogs(db, path, actor="analyst", fmt="aws")


K8S_INVENTORY = {
    "nodes": {
        "items": [
            {
                "metadata": {"name": "node-a"},
                "status": {
                    "addresses": [{"type": "InternalIP", "address": "10.10.0.1"}]
                },
            }
        ]
    },
    "pods": {
        "items": [
            {
                "metadata": {
                    "name": "web-1",
                    "namespace": "prod",
                    "labels": {"app": "web", "tier": "frontend"},
                },
                "spec": {
                    "nodeName": "node-a",
                    "containers": [{"ports": [{"containerPort": 8080}]}],
                },
                "status": {"podIP": "10.10.0.11"},
            },
            {
                "metadata": {
                    "name": "api-1",
                    "namespace": "prod",
                    "labels": {"app": "api"},
                },
                "spec": {"nodeName": "node-a"},
                "status": {"podIP": "10.10.0.12"},
            },
        ]
    },
    "services": {
        "items": [
            {
                "metadata": {"name": "web-svc", "namespace": "prod"},
                "spec": {
                    "clusterIP": "10.10.0.100",
                    "selector": {"app": "web"},
                    "ports": [{"port": 80}],
                },
            }
        ]
    },
    "namespaces": {"items": [{"metadata": {"name": "prod"}}]},
}


def test_k8s_import_and_correlation(db: Database) -> None:
    result = k8s_mod.import_inventory(db, K8S_INVENTORY, actor="analyst", label="prod")
    assert result["pod"] == 2
    assert result["service"] == 1
    assert result["node"] == 1
    assert result["namespace"] == 1

    with db.connect() as conn:
        entities = k8s_mod.list_entities(conn, kind="pod")
        assert len(entities) == 2
        assert any(e["ip"] == "10.10.0.12" for e in entities)
        packets_store.upsert_flows(
            conn,
            [
                {
                    "capture_id": CAPTURE_ID,
                    "src": "10.10.0.11",
                    "dst": "10.10.0.12",
                    "proto": "tcp",
                    "dport": 8080,
                    "packets": 25,
                    "bytes": 9000,
                    "first_ts": 1700000000.0,
                    "last_ts": 1700000010.0,
                },
                {
                    "capture_id": CAPTURE_ID,
                    "src": "10.10.0.12",
                    "dst": "93.184.216.34",
                    "proto": "tcp",
                    "dport": 443,
                    "packets": 60,
                    "bytes": 42000,
                    "first_ts": 1700000001.0,
                    "last_ts": 1700000020.0,
                },
            ],
        )
        correlation = k8s_mod.correlate_capture(conn, CAPTURE_ID)
        events = list_events(conn)

    assert correlation["pods_known"] == 2
    assert correlation["matched"] == 2
    pod_flow = next(f for f in correlation["flows"] if f["dst"] == "10.10.0.12")
    assert pod_flow["src_pod"]["name"] == "web-1"
    assert pod_flow["src_pod"]["node"] == "node-a"
    assert pod_flow["dst_pod"]["name"] == "api-1"
    assert pod_flow["src_services"][0]["name"] == "web-svc"
    assert any(event["action"] == "K8S_IMPORTED" for event in events)


def test_k8s_invalid_inventory(db: Database) -> None:
    with pytest.raises(k8s_mod.K8sError):
        k8s_mod.import_inventory(db, {}, actor="analyst")


@pytest.fixture()
def client(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path)
    app = create_app(config)
    with app.state.db.connect() as conn:
        create_user(conn, "testadmin", "admin-pw-123", "admin")
        create_user(conn, "testanalyst", "analyst-pw-123", "analyst")
        create_user(conn, "testauditor", "auditor-pw-123", "auditor")
        packets_store.create_capture(
            conn,
            capture_id=CAPTURE_ID,
            created_at="2026-10-19T00:00:00+00:00",
            interface="lo",
            profile="C",
            source="import",
            bpf=None,
        )
    with TestClient(app) as test_client:
        yield test_client


def _login(client: TestClient, username: str, password: str) -> dict:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_api_flowlog_import_permissions(client: TestClient, tmp_path: Path) -> None:
    path = tmp_path / "flows.csv"
    path.write_text(GENERIC_CSV)

    auditor = _login(client, "testauditor", "auditor-pw-123")
    denied = client.post(
        "/api/integrations/flowlogs",
        json={"path": str(path)},
        headers={"X-CSRF-Token": auditor["csrf_token"]},
    )
    assert denied.status_code == 403

    analyst = _login(client, "testanalyst", "analyst-pw-123")
    no_csrf = client.post("/api/integrations/flowlogs", json={"path": str(path)})
    assert no_csrf.status_code == 403
    imported = client.post(
        "/api/integrations/flowlogs",
        json={"path": str(path), "format": "generic-csv", "label": "csv-flows"},
        headers={"X-CSRF-Token": analyst["csrf_token"]},
    )
    assert imported.status_code == 200, imported.text
    body = imported.json()
    assert body["records"] == 2
    captured = client.get(f"/api/captures/{body['capture_id']}").json()
    assert captured["source"] == "cloud-flowlog"


def test_api_k8s_import_and_endpoints(client: TestClient) -> None:
    auditor = _login(client, "testauditor", "auditor-pw-123")
    denied = client.post(
        "/api/integrations/k8s",
        json={"inventory": K8S_INVENTORY},
        headers={"X-CSRF-Token": auditor["csrf_token"]},
    )
    assert denied.status_code == 403
    assert client.get("/api/captures/%s/tunnels" % CAPTURE_ID).status_code == 200

    analyst = _login(client, "testanalyst", "analyst-pw-123")
    imported = client.post(
        "/api/integrations/k8s",
        json={"inventory": K8S_INVENTORY, "label": "prod"},
        headers={"X-CSRF-Token": analyst["csrf_token"]},
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["pod"] == 2
    entities = client.get("/api/k8s/entities?kind=service").json()
    assert entities["entities"][0]["name"] == "web-svc"
    correlation = client.get(
        f"/api/captures/{CAPTURE_ID}/k8s-correlation"
    ).json()
    assert correlation["pods_known"] == 2
    tunnels = client.get(f"/api/captures/{CAPTURE_ID}/tunnels").json()
    assert tunnels["tunnels"] == []


def test_api_flowlog_import_blocked_by_emergency(
    client: TestClient, tmp_path: Path
) -> None:
    analyst = _login(client, "testanalyst", "analyst-pw-123")
    client.app.state.emergency.trigger(actor="testanalyst", reason="test")
    path = tmp_path / "flows.csv"
    path.write_text(GENERIC_CSV)
    blocked = client.post(
        "/api/integrations/flowlogs",
        json={"path": str(path)},
        headers={"X-CSRF-Token": analyst["csrf_token"]},
    )
    assert blocked.status_code == 423
