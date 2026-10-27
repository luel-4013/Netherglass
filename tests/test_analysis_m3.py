"""M3 tests: protocol extraction, query compiler, correlation store, API."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netherglass.analysis import protocols
from netherglass.analysis.query import QueryError, compile_query
from netherglass.api.app import create_app
from netherglass.capture import decode as decode_mod
from netherglass.config import AppConfig
from netherglass.security.auth import create_user
from netherglass.store import analysis as analysis_store
from netherglass.store import packets as packets_store
from netherglass.store.db import Database

CAPTURE_ID = "cap-20261019-test-0001"


# --------------------------------------------------------------- fixtures


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
            profile="B",
            source="live",
            bpf=None,
        )
    return database


def _normalized(**fields) -> dict:
    """Build a normalized packet the same way decode.py does."""
    layers = {
        key: [str(item) for item in value]
        if isinstance(value, (list, tuple))
        else [str(value)]
        for key, value in fields.items()
    }
    return decode_mod.normalize_ek(layers, timestamp="2026-10-19T10:00:00.000000000Z")


# --------------------------------------------------------------- protocols


def test_extract_dns_query_and_response() -> None:
    query_fields = {
        "dns_dns_qry_name": "example.com",
        "dns_dns_qry_type": "1",
        "dns_dns_flags_response": "0",
        "dns_dns_id": "4660",
    }
    query = protocols.extract_dns(query_fields)
    assert query is not None
    assert query["qname"] == "example.com"
    assert query["qtype"] == "A"
    assert query["is_response"] is False
    assert query["rcode"] is None
    assert query["transaction_id"] == 0x1234

    response_fields = {
        "dns_dns_qry_name": "example.com",
        "dns_dns_qry_type": "1",
        "dns_dns_flags_response": "1",
        "dns_dns_flags_rcode": "0",
        "dns_dns_a": ["93.184.216.34", "93.184.216.35"],
        "dns_dns_cname": ["www.example.com"],
        "dns_dns_resp_ttl": [300, 60],
    }
    response = protocols.extract_dns(response_fields)
    assert response is not None
    assert response["is_response"] is True
    assert response["rcode"] == "NOERROR"
    assert response["answers"] == ["93.184.216.34", "93.184.216.35"]
    assert response["cnames"] == ["www.example.com"]
    assert response["ttl_min"] == 60


def test_extract_dns_rcode_name_and_not_dns() -> None:
    fields = {"dns_dns_qry_name": "x.test", "dns_dns_flags_response": "1", "dns_dns_flags_rcode": "3"}
    assert protocols.extract_dns(fields)["rcode"] == "NXDOMAIN"
    assert protocols.extract_dns({"tcp_tcp_srcport": "80"}) is None


def test_extract_http_sanitizes_query_values() -> None:
    fields = {
        "http_http_request": "1",
        "http_http_request_method": "GET",
        "http_http_host": "api.example.com",
        "http_http_request_uri": "/v1/users?id=42&token=SECRET#frag",
        "http_http_user_agent": "curl/8.22.0",
        "http_http_authorization": "Bearer abc.def.ghi",
        "http_http_cookie": ["session=SECRETVALUE", "theme=dark"],
        "http_http_set_cookie": ["id=SECRETSETTING"],
        "http_http_request_version": "HTTP/1.1",
    }
    http = protocols.extract_http(fields, stream="3")
    assert http is not None
    assert http["kind"] == "request"
    assert http["path"] == "/v1/users"
    assert http["query_names"] == ["id", "token"]
    assert http["auth_scheme"] == "Bearer"
    assert http["cookie_count"] == 2
    dumped = repr(http)
    assert "SECRET" not in dumped
    assert "Bearer abc" not in dumped
    assert "session=" not in dumped


def test_http_info_hides_query_values() -> None:
    fields = {
        "http_http_request": "1",
        "http_http_request_method": "POST",
        "http_http_host": "bank.example",
        "http_http_request_uri": "/transfer?amount=1000&to=12345",
    }
    info = decode_mod._build_info(fields, "http")
    assert info == "HTTP POST bank.example/transfer?…"
    assert "amount" not in info
    assert "1000" not in info


def test_extract_tls_client_hello_and_server_hello() -> None:
    client = protocols.extract_tls(
        {
            "tls_tls_handshake_type": "1",
            "tls_tls_handshake_extensions_server_name": "example.com",
            "tls_tls_handshake_extensions_alpn_str": "h2,http/1.1",
            "tls_tls_handshake_extensions_supported_version": "772",
            "tls_tls_handshake_ja3_full": "771,4865-4866,0-11,29,0",
            "tls_tls_handshake_ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
        },
        stream="7",
    )
    assert client is not None
    assert client["kind"] == "client_hello"
    assert client["sni"] == "example.com"
    assert client["alpn"] == "h2,http/1.1"
    assert client["version"] == "TLS1.3"
    assert client["cipher"] is None
    assert client["ja4"].startswith("t13d")

    server = protocols.extract_tls(
        {
            "tls_tls_handshake_type": "2",
            "tls_tls_handshake_ciphersuite": "4865",
            "tls_tls_handshake_extensions_supported_version": "772",
        },
        stream="7",
    )
    assert server is not None
    assert server["kind"] == "server_hello"
    assert server["cipher"] == "TLS_AES_128_GCM_SHA256"


def test_extract_tls_certificate_validity() -> None:
    fields = {
        "tls_tls_handshake_type": "11",
        "x509af_x509af_utcTime": ["260101000000Z", "270101000000Z"],
        "x509af_x509af_version": "2",
    }
    tls = protocols.extract_tls(fields, stream="9")
    assert tls["kind"] == "certificate"
    assert tls["cert_not_before"] == "260101000000Z"
    assert tls["cert_not_after"] == "270101000000Z"
    assert tls["cert_count"] == 1
    assert protocols.extract_tls({"tcp_tcp_srcport": "443"}, stream="9") is None


def test_enrich_sets_searchable_columns() -> None:
    packet = _normalized(
        frame_frame_protocols="eth:ethertype:ip:tcp:tls",
        ip_ip_src="10.0.0.5",
        ip_ip_dst="10.0.0.9",
        tcp_tcp_srcport="51000",
        tcp_tcp_dstport="443",
        tcp_tcp_stream="4",
        eth_eth_src="aa:bb:cc:dd:ee:01",
        eth_eth_dst="aa:bb:cc:dd:ee:02",
        tls_tls_handshake_type="1",
        tls_tls_handshake_extensions_server_name="example.org",
    )
    assert packet["src_mac"] == "aa:bb:cc:dd:ee:01"
    assert packet["dst_mac"] == "aa:bb:cc:dd:ee:02"
    assert packet["stream"] == "4"
    assert packet["tls_sni"] == "example.org"
    assert packet["app_proto"] == "tls"
    assert packet["encryption"] == "encrypted"

    dns_packet = _normalized(
        frame_frame_protocols="eth:ethertype:ip:udp:dns",
        ip_ip_src="10.0.0.5",
        ip_ip_dst="10.0.0.1",
        udp_udp_srcport="40000",
        udp_udp_dstport="53",
        dns_dns_qry_name="example.com",
        dns_dns_qry_type="1",
    )
    assert dns_packet["dns_qname"] == "example.com"
    assert dns_packet["dns_qtype"] == "A"
    assert dns_packet["encryption"] == "plaintext"

    tcp_packet = _normalized(
        frame_frame_protocols="eth:ethertype:ip:tcp",
        ip_ip_src="10.0.0.5",
        ip_ip_dst="10.0.0.9",
        tcp_tcp_srcport="51001",
        tcp_tcp_dstport="9000",
    )
    assert tcp_packet["encryption"] == "unknown"


# --------------------------------------------------------------- query


def test_query_precedence_and_parens() -> None:
    where, params = compile_query("proto = dns OR proto = tls AND port = 443")
    assert where == (
        "(LOWER(COALESCE(app_proto, proto)) = LOWER(?) OR "
        "(LOWER(COALESCE(app_proto, proto)) = LOWER(?) AND (sport = ? OR dport = ?)))"
    )
    assert params == ["dns", "tls", 443, 443]

    where, params = compile_query("(proto = dns OR proto = tls) AND port = 443")
    assert where.startswith("(((LOWER(COALESCE(app_proto, proto)) = LOWER(?) OR")
    assert params == ["dns", "tls", 443, 443]

    where, params = compile_query("NOT proto = dns")
    assert where == "(NOT LOWER(COALESCE(app_proto, proto)) = LOWER(?))"
    assert params == ["dns"]


def test_query_tilde_and_word_operators() -> None:
    where, params = compile_query('dns.name ~ "example"')
    assert "LIKE LOWER(?) ESCAPE" in where
    assert params == ["%example%"]

    where, params = compile_query("tls.sni startswith cloudflare")
    assert params == ["cloudflare%"]

    where, params = compile_query("http.host endswith '.example.com'")
    assert params == ["%.example.com"]


def test_query_escapes_wildcards() -> None:
    _, params = compile_query('dns.name contains "100%_evil"')
    assert params == ["%100\\%\\_evil%"]


def test_query_rejects_unknown_and_deferred_fields() -> None:
    with pytest.raises(QueryError, match="unknown field"):
        compile_query("bogus.field = 1")
    with pytest.raises(QueryError, match="EVIDENCE tab"):
        compile_query("sensitive_data.detected = 1")
    with pytest.raises(QueryError, match="FINDINGS tab"):
        compile_query("finding.severity = high")


def test_query_rejects_bad_operator_and_syntax() -> None:
    with pytest.raises(QueryError, match="expects a number"):
        compile_query("port = abc")
    with pytest.raises(QueryError, match="not valid for"):
        compile_query("port contains 80")
    with pytest.raises(QueryError, match="missing closing parenthesis"):
        compile_query("(proto = dns")
    with pytest.raises(QueryError, match="empty query"):
        compile_query("   ")
    with pytest.raises(QueryError, match="unexpected token"):
        compile_query("proto = dns proto")


def test_query_injection_is_parameterized() -> None:
    where, params = compile_query("dns.name = \"x' OR 1=1 --\"")
    assert "OR 1=1" not in where
    assert params == ["x' OR 1=1 --"]
    assert where.count("?") == 1


# --------------------------------------------------------------- correlation


def _dns_packet(num: int, ts: float, src: str, dst: str, **dns_fields) -> dict:
    return _normalized(
        frame_frame_protocols="eth:ethertype:ip:udp:dns",
        frame_frame_number=str(num),
        ip_ip_src=src,
        ip_ip_dst=dst,
        udp_udp_srcport="40000",
        udp_udp_dstport="53",
        frame_frame_time_epoch=f"2026-10-19T10:00:{int(ts):02d}.000000000Z",
        dns_dns_qry_name=dns_fields.get("qname", "example.com"),
        dns_dns_qry_type=dns_fields.get("qtype", "1"),
        dns_dns_flags_response=dns_fields.get("response", "0"),
        **({"dns_dns_flags_rcode": dns_fields["rcode"]} if "rcode" in dns_fields else {}),
        **({"dns_dns_a": dns_fields["answers"]} if "answers" in dns_fields else {}),
        **({"dns_dns_resp_ttl": dns_fields["ttls"]} if "ttls" in dns_fields else {}),
    )


def test_dns_response_correlation(db: Database) -> None:
    with db.connect() as conn:
        query = _dns_packet(1, 10, "10.0.0.5", "10.0.0.1")
        answer = _dns_packet(
            2, 11, "10.0.0.1", "10.0.0.5",
            response="1", rcode="0", answers="93.184.216.34", ttls="60",
        )
        analysis_store.record_batch(conn, CAPTURE_ID, [query, answer])
        rows = conn.execute(
            "SELECT * FROM dns_events WHERE capture_id = ?", (CAPTURE_ID,)
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["matched"] == 1
    assert rows[0]["rcode"] == "NOERROR"
    assert rows[0]["answers"] == '["93.184.216.34"]'
    assert rows[0]["ttl_min"] == 60
    assert rows[0]["response_num"] == 2

    with db.connect() as conn:
        orphan = _dns_packet(
            3, 12, "10.0.0.1", "10.0.0.5",
            qname="orphan.test", response="1", rcode="3",
        )
        analysis_store.record_batch(conn, CAPTURE_ID, [orphan])
        rows = conn.execute(
            "SELECT matched, rcode FROM dns_events WHERE qname = 'orphan.test'"
        ).fetchall()
    assert rows[0]["matched"] == 2
    assert rows[0]["rcode"] == "NXDOMAIN"


def test_dns_hostnames_and_host_counters(db: Database) -> None:
    with db.connect() as conn:
        query = _dns_packet(1, 10, "10.0.0.5", "10.0.0.1")
        answer = _dns_packet(
            2, 11, "10.0.0.1", "10.0.0.5",
            response="1", rcode="0", answers="93.184.216.34", ttls="60",
        )
        analysis_store.record_batch(conn, CAPTURE_ID, [query, answer])
        hosts = {row["ip"]: row for row in analysis_store.list_hosts(conn, CAPTURE_ID)}
        names = conn.execute(
            "SELECT ip, name, source FROM host_names WHERE capture_id = ? ORDER BY ip, source",
            (CAPTURE_ID,),
        ).fetchall()
    assert hosts["10.0.0.5"]["sent_packets"] == 1
    assert hosts["10.0.0.5"]["recv_packets"] == 1
    assert hosts["10.0.0.5"]["hostname"] == "example.com"
    assert hosts["10.0.0.1"]["hostname"] is None
    named = {(row["ip"], row["name"], row["source"]) for row in names}
    assert ("10.0.0.5", "example.com", "dns_query") in named
    assert ("93.184.216.34", "example.com", "dns_answer") in named


def test_http_response_correlation(db: Database) -> None:
    request = _normalized(
        frame_frame_protocols="eth:ethertype:ip:tcp:http",
        frame_frame_number="10",
        ip_ip_src="10.0.0.5",
        ip_ip_dst="93.184.216.34",
        tcp_tcp_srcport="52000",
        tcp_tcp_dstport="80",
        tcp_tcp_stream="5",
        http_http_request="1",
        http_http_request_method="GET",
        http_http_host="example.com",
        http_http_request_uri="/index.html?a=1",
        http_http_user_agent="curl/8.22.0",
    )
    response = _normalized(
        frame_frame_protocols="eth:ethertype:ip:tcp:http",
        frame_frame_number="11",
        ip_ip_src="93.184.216.34",
        ip_ip_dst="10.0.0.5",
        tcp_tcp_srcport="80",
        tcp_tcp_dstport="52000",
        tcp_tcp_stream="5",
        http_http_response="1",
        http_http_response_code="404",
        http_http_content_type="text/html",
        http_http_server="nginx",
    )
    with db.connect() as conn:
        analysis_store.record_batch(conn, CAPTURE_ID, [request, response])
        rows = conn.execute(
            "SELECT kind, method, host, path, query_names, status, content_type, server "
            "FROM http_events WHERE capture_id = ? ORDER BY ts, id",
            (CAPTURE_ID,),
        ).fetchall()
        host_row = conn.execute(
            "SELECT hostname, hostname_source FROM hosts WHERE capture_id = ? AND ip = '93.184.216.34'",
            (CAPTURE_ID,),
        ).fetchone()
    assert len(rows) == 2
    request_row = next(row for row in rows if row["kind"] == "request")
    assert request_row["status"] == 404
    assert request_row["path"] == "/index.html"
    assert request_row["query_names"] == '["a"]'
    assert request_row["content_type"] == "text/html"
    assert host_row["hostname"] == "example.com"
    assert host_row["hostname_source"] == "http_host"


def test_tls_session_merge_and_certificate_pass(db: Database) -> None:
    client_hello = _normalized(
        frame_frame_protocols="eth:ethertype:ip:tcp:tls",
        ip_ip_src="10.0.0.5",
        ip_ip_dst="10.0.0.10",
        tcp_tcp_srcport="51000",
        tcp_tcp_dstport="443",
        tcp_tcp_stream="6",
        tls_tls_handshake_type="1",
        tls_tls_handshake_extensions_server_name="cloudflare-dns.com",
        tls_tls_handshake_ja4="t13d1516h2_8daaf6152771_b0da82dd1658",
    )
    server_hello = _normalized(
        frame_frame_protocols="eth:ethertype:ip:tcp:tls",
        ip_ip_src="10.0.0.10",
        ip_ip_dst="10.0.0.5",
        tcp_tcp_srcport="443",
        tcp_tcp_dstport="51000",
        tcp_tcp_stream="6",
        tls_tls_handshake_type="2",
        tls_tls_handshake_ciphersuite="4866",
        tls_tls_handshake_extensions_supported_version="772",
    )
    certificate = _normalized(
        frame_frame_protocols="eth:ethertype:ip:tcp:tls",
        ip_ip_src="10.0.0.10",
        ip_ip_dst="10.0.0.5",
        tcp_tcp_srcport="443",
        tcp_tcp_dstport="51000",
        tcp_tcp_stream="6",
        tls_tls_handshake_type="11",
        x509af_x509af_utcTime=["260101000000Z", "270101000000Z"],
    )
    with db.connect() as conn:
        analysis_store.record_batch(
            conn, CAPTURE_ID, [client_hello, server_hello, certificate]
        )
        row = conn.execute(
            "SELECT * FROM tls_sessions WHERE capture_id = ? AND stream = '6'",
            (CAPTURE_ID,),
        ).fetchone()
        # certificate pass arriving before record_batch must still merge
        analysis_store.apply_tls_certificates(
            conn,
            CAPTURE_ID,
            [{"stream": "6", "frame": 3, "sans": ["cloudflare-dns.com"], "name_strings": ["Cloudflare"]}],
        )
        analysis_store.record_batch(conn, CAPTURE_ID, [client_hello])
        row2 = conn.execute(
            "SELECT sni, cert_sans FROM tls_sessions WHERE capture_id = ? AND stream = '6'",
            (CAPTURE_ID,),
        ).fetchone()
        names = conn.execute(
            "SELECT name, source FROM host_names WHERE capture_id = ? AND ip = '10.0.0.10'",
            (CAPTURE_ID,),
        ).fetchall()
    assert row["client"] == "10.0.0.5"
    assert row["server"] == "10.0.0.10"
    assert row["version"] == "TLS1.3"
    assert row["sni"] == "cloudflare-dns.com"
    assert row["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert row["cert_not_before"] == "260101000000Z"
    assert row2["sni"] == "cloudflare-dns.com"
    assert row2["cert_sans"] == '["cloudflare-dns.com"]'
    named = {(item["name"], item["source"]) for item in names}
    assert ("cloudflare-dns.com", "tls_cert_san") in named


def test_hostname_rank_and_server_names(db: Database) -> None:
    with db.connect() as conn:
        dns_query = _dns_packet(1, 10, "10.0.0.5", "10.0.0.1", qname="hint.example")
        analysis_store.record_batch(conn, CAPTURE_ID, [dns_query])
        tls_packet = _normalized(
            frame_frame_protocols="eth:ethertype:ip:tcp:tls",
            ip_ip_src="10.0.0.5",
            ip_ip_dst="10.0.0.9",
            tcp_tcp_srcport="51000",
            tcp_tcp_dstport="443",
            tcp_tcp_stream="8",
            tls_tls_handshake_type="1",
            tls_tls_handshake_extensions_server_name="real.example",
        )
        analysis_store.record_batch(conn, CAPTURE_ID, [tls_packet])
        later_dns = _dns_packet(2, 12, "10.0.0.5", "10.0.0.1", qname="weaker.example")
        analysis_store.record_batch(conn, CAPTURE_ID, [later_dns])
        client_row = conn.execute(
            "SELECT hostname, hostname_source FROM hosts WHERE capture_id = ? AND ip = '10.0.0.5'",
            (CAPTURE_ID,),
        ).fetchone()
        server_row = conn.execute(
            "SELECT hostname, hostname_source FROM hosts WHERE capture_id = ? AND ip = '10.0.0.9'",
            (CAPTURE_ID,),
        ).fetchone()
        detail = analysis_store.get_host(conn, CAPTURE_ID, "10.0.0.5")
    assert server_row["hostname"] == "real.example"
    assert server_row["hostname_source"] == "tls_sni"
    assert client_row["hostname"] == "hint.example"
    assert client_row["hostname_source"] == "dns_query"
    assert detail is not None
    assert any(item["name"] == "hint.example" for item in detail["names"])
    assert any(item["name"] == "weaker.example" for item in detail["names"])


# --------------------------------------------------------------- stats


def test_stats_and_filters(db: Database) -> None:
    with db.connect() as conn:
        query = _dns_packet(1, 10, "10.0.0.5", "10.0.0.1")
        answer = _dns_packet(
            2, 11, "10.0.0.1", "10.0.0.5",
            response="1", rcode="0", answers="93.184.216.34", ttls="60",
        )
        analysis_store.record_batch(conn, CAPTURE_ID, [query, answer])
        stats = analysis_store.stats(conn, CAPTURE_ID)
        dns_page = analysis_store.list_dns(conn, CAPTURE_ID, qname="example", limit=1)
        empty_page = analysis_store.list_dns(conn, CAPTURE_ID, rcode="NXDOMAIN")
        http_page = analysis_store.list_http(conn, CAPTURE_ID, method="GET")
        tls_page = analysis_store.list_tls(conn, CAPTURE_ID, sni="nothing")
    assert stats["dns_summary"]["queries"] >= 1
    assert any(item["qname"] == "example.com" for item in stats["top_domains"])
    assert any(item["ip"] == "10.0.0.5" for item in stats["top_talkers"])
    assert "top_protocols" in stats
    assert "security" in stats
    assert stats["findings"]["available"] is True
    assert stats["sensitive_data"]["available"] is True
    assert dns_page["total"] == 1
    assert empty_page["total"] == 0
    assert http_page["total"] == 0
    assert tls_page["total"] == 0


def test_search_packets_store(db: Database) -> None:
    with db.connect() as conn:
        packet = _normalized(
            frame_frame_protocols="eth:ethertype:ip:tcp:http",
            frame_frame_number="10",
            ip_ip_src="10.0.0.5",
            ip_ip_dst="93.184.216.34",
            tcp_tcp_srcport="52000",
            tcp_tcp_dstport="80",
            tcp_tcp_stream="5",
            http_http_request="1",
            http_http_request_method="GET",
            http_http_host="example.com",
            http_http_request_uri="/index.html",
        )
        packet["capture_id"] = CAPTURE_ID
        packets_store.insert_packets(conn, [packet])
        where, params = compile_query("http.host ~ example AND app.proto = http")
        result = packets_store.search_packets(
            conn, CAPTURE_ID, where, params, limit=10, offset=0
        )
        missing = packets_store.search_packets(
            conn, CAPTURE_ID, "dns_qname = ?", ["nope"], limit=10, offset=0
        )
    assert result["total"] == 1
    assert result["packets"][0]["http_host"] == "example.com"
    assert result["packets"][0]["app_proto"] == "http"
    assert missing["total"] == 0


# --------------------------------------------------------------- API


@pytest.fixture()
def client(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path)
    app = create_app(config)
    with app.state.db.connect() as conn:
        create_user(conn, "testadmin", "admin-pw-123", "admin")
        packets_store.create_capture(
            conn,
            capture_id=CAPTURE_ID,
            created_at="2026-10-19T00:00:00+00:00",
            interface="lo",
            profile="B",
            source="live",
            bpf=None,
        )
    with TestClient(app) as test_client:
        yield test_client


def _login(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login", json={"username": "testadmin", "password": "admin-pw-123"}
    )
    assert response.status_code == 200, response.text


def test_analysis_endpoints_require_auth(client: TestClient) -> None:
    for url in (
        f"/api/captures/{CAPTURE_ID}/hosts",
        f"/api/captures/{CAPTURE_ID}/dns",
        f"/api/captures/{CAPTURE_ID}/http",
        f"/api/captures/{CAPTURE_ID}/tls",
        f"/api/captures/{CAPTURE_ID}/stats",
        f"/api/search?capture_id={CAPTURE_ID}&q=proto%20%3D%20dns",
        "/api/search/fields",
    ):
        assert client.get(url).status_code == 401, url


def test_search_endpoint_and_errors(client: TestClient) -> None:
    _login(client)
    ok = client.get(
        f"/api/search?capture_id={CAPTURE_ID}&q=port%20%3D%20443"
    )
    assert ok.status_code == 200
    assert ok.json()["total"] == 0
    assert ok.json()["packets"] == []

    bad = client.get(f"/api/search?capture_id={CAPTURE_ID}&q=bogus%20%3D%201")
    assert bad.status_code == 400
    assert "unknown field" in bad.json()["detail"]

    deferred = client.get(
        f"/api/search?capture_id={CAPTURE_ID}&q=finding.severity%20%3D%201"
    )
    assert deferred.status_code == 400
    assert "FINDINGS tab" in deferred.json()["detail"]

    missing = client.get(f"/api/search?capture_id=nope&q=port%20%3D%20443")
    assert missing.status_code == 404

    fields = client.get("/api/search/fields").json()
    assert "dns.name" in fields["fields"]
    assert "sensitive_data.detected" in fields["deferred"]


def test_analysis_endpoints_list_filters(client: TestClient) -> None:
    _login(client)
    hosts = client.get(f"/api/captures/{CAPTURE_ID}/hosts")
    assert hosts.status_code == 200
    assert hosts.json()["hosts"] == []
    dns = client.get(f"/api/captures/{CAPTURE_ID}/dns?qname=example&limit=10")
    assert dns.status_code == 200
    assert dns.json()["total"] == 0
    http = client.get(f"/api/captures/{CAPTURE_ID}/http?method=get")
    assert http.status_code == 200
    bad_kind = client.get(f"/api/captures/{CAPTURE_ID}/http?kind=bogus")
    assert bad_kind.status_code == 422
    stats = client.get(f"/api/captures/{CAPTURE_ID}/stats")
    assert stats.status_code == 200
    assert "top_talkers" in stats.json()
    missing = client.get("/api/captures/cap-missing/hosts")
    assert missing.status_code == 404
