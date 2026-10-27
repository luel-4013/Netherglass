"""Protocol-specific metadata extraction from tshark EK flat fields.

Design rules (spec sections 11-13, privacy rules):
- Metadata only: payload bytes, Authorization/Cookie values, query-string
  values and full URLs are NEVER copied into the database.
- Anything uncertain is reported as unknown instead of guessed.
- Encryption classification is a coarse label for search; full connection
  security grading belongs to the Phase 3 detection engine.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    257: "CAA",
}

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}

TLS_VERSIONS = {
    0x0300: "SSLv3",
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
}

CIPHER_NAMES = {
    "4865": "TLS_AES_128_GCM_SHA256",
    "4866": "TLS_AES_256_GCM_SHA384",
    "4867": "TLS_CHACHA20_POLY1305_SHA256",
    "49195": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "49196": "ECDHE-ECDSA-AES256-GCM-SHA384",
    "49199": "ECDHE-RSA-AES128-GCM-SHA256",
    "49200": "ECDHE-RSA-AES256-GCM-SHA384",
    "52392": "ECDHE-RSA-CHACHA20-POLY1305",
    "52393": "ECDHE-ECDSA-CHACHA20-POLY1305",
    "49161": "ECDHE-ECDSA-AES128-SHA",
    "49162": "ECDHE-ECDSA-AES256-SHA",
    "49171": "ECDHE-RSA-AES128-SHA",
    "49172": "ECDHE-RSA-AES256-SHA",
    "5": "RSA_WITH_RC4_128_SHA",
    "10": "RSA_WITH_3DES_EDE_CBC_SHA",
    "47": "RSA_WITH_AES_128_CBC_SHA",
    "53": "RSA_WITH_AES_256_CBC_SHA",
}

PLAINTEXT_APPS = {
    "http",
    "dns",
    "mdns",
    "dhcp",
    "dhcpv6",
    "ftp",
    "telnet",
    "smtp",
    "imap",
    "pop3",
    "ldap",
    "kerberos",
    "ntp",
    "tftp",
    "snmp",
    "radius",
    "syslog",
    "stp",
}

ENCRYPTED_APPS = {"tls", "quic", "ssh", "wireguard", "openvpn", "ipsec", "esp", "isakmp"}

DATA_PLAINTEXT_APPS = {
    "http",
    "ftp",
    "telnet",
    "smtp",
    "imap",
    "pop3",
    "ldap",
    "snmp",
    "radius",
    "syslog",
}

WEAK_TLS_VERSIONS = {"TLS1.0", "TLS1.1"}
_INSECURE_CIPHER_MARKERS = ("RC4", "3DES", "DES_", "_DES", "EXPORT", "NULL", "MD5")
_WEAK_CIPHER_MARKERS = ("CBC",)
_GOOD_CIPHER_MARKERS = ("GCM", "CHACHA20", "POLY1305")

APP_ALIASES = {
    "http2": "http",
    "http3": "http",
    "ssl": "tls",
    "dtls": "tls",
    "mdns": "dns",
    "llmnr": "dns",
    "dhcpv6": "dhcp",
}

_TLS_HANDSHAKE_CLIENT_HELLO = "1"
_TLS_HANDSHAKE_SERVER_HELLO = "2"
_TLS_HANDSHAKE_CERTIFICATE = "11"

_MAX_NAME = 255
_MAX_QUERY_PARAMS = 32


def _s(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:_MAX_NAME] if text else None


def _i(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _b(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes")


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = [value]
    out: list[str] = []
    for item in items:
        text = _s(item)
        if text is not None:
            out.append(text)
    return out


def qtype_name(value: Any) -> str | None:
    number = _i(value)
    if number is None:
        return _s(value)
    return QTYPE_NAMES.get(number, f"TYPE{number}" if number >= 0 else None)


def rcode_name(value: Any) -> str | None:
    number = _i(value)
    if number is None:
        return _s(value)
    return RCODE_NAMES.get(number, f"RCODE{number}" if number >= 0 else None)


def tls_version_name(value: Any) -> str | None:
    number = _i(value)
    if number is None:
        return _s(value)
    return TLS_VERSIONS.get(number, f"0x{number:04x}")


def sanitize_http_path(uri: str | None) -> tuple[str | None, list[str]]:
    """Return (path, query_parameter_names). Values are deliberately dropped."""
    raw = _s(uri)
    if raw is None:
        return None, []
    split = urlsplit(raw)
    path = split.path or None
    names: list[str] = []
    for name, _ in parse_qsl(split.query, keep_blank_values=True)[:_MAX_QUERY_PARAMS]:
        clean = _s(name)
        if clean and clean not in names:
            names.append(clean)
    return path, names


def http_display_uri(host: str | None, path: str | None, has_query: bool) -> str:
    base = f"{host or ''}{path or ''}"
    return f"{base}?…" if has_query else base


def _rebuild_without_query(uri: str | None) -> str | None:
    raw = _s(uri)
    if raw is None:
        return None
    split = urlsplit(raw)
    if not split.query:
        return raw
    return urlunsplit((split.scheme, split.netloc, split.path, "<redacted>", ""))


def classify_encryption(proto: str | None, app_proto: str | None) -> str:
    app = (app_proto or "").lower()
    kind = (proto or "").lower()
    if app in ENCRYPTED_APPS or kind in ENCRYPTED_APPS:
        return "encrypted"
    if app in PLAINTEXT_APPS or kind in PLAINTEXT_APPS:
        return "plaintext"
    return "unknown"


def classify_security(
    encryption: str | None,
    app_proto: str | None,
    *,
    version: str | None = None,
    cipher: str | None = None,
) -> str:
    """Security quality axis (spec section 10): GOOD / WEAK / INSECURE / UNKNOWN.

    Honesty rule: infrastructure protocols that are plaintext by design
    (DNS, DHCP, NTP, ARP, ...) are reported UNKNOWN here; whether that is a
    problem depends on context and is handled by detection rules instead of
    blanket grading.
    """
    app = (app_proto or "").lower()
    kind = (encryption or "").lower()
    if kind == "encrypted":
        if app == "ssh" or app in ("wireguard", "openvpn"):
            return "good"
        if version == "SSLv3":
            return "insecure"
        upper_cipher = (cipher or "").upper()
        if any(marker in upper_cipher for marker in _INSECURE_CIPHER_MARKERS):
            return "insecure"
        if version in WEAK_TLS_VERSIONS:
            return "weak"
        if any(marker in upper_cipher for marker in _GOOD_CIPHER_MARKERS):
            return "good"
        if any(marker in upper_cipher for marker in _WEAK_CIPHER_MARKERS):
            return "weak"
        if upper_cipher or version in ("TLS1.2", "TLS1.3"):
            return "good"
        return "unknown"
    if kind == "plaintext":
        return "insecure" if app in DATA_PLAINTEXT_APPS else "unknown"
    return "unknown"


def app_protocol(proto: str | None) -> str | None:
    if not proto:
        return None
    kind = proto.lower()
    if kind in ("tcp", "udp", "sctp", "icmp", "icmpv6", "arp", "stp", "igmp", "llc", "data", "unknown"):
        return None
    return APP_ALIASES.get(kind, kind)


TUNNEL_KINDS: dict[str, tuple[str, str, int]] = {
    "esp": ("ipsec-esp", "DATA", 0),
    "ah": ("ipsec-ah", "DATA", 0),
    "isakmp": ("ipsec-ike", "HANDSHAKE", 0),
    "ike": ("ipsec-ike", "HANDSHAKE", 0),
    "wireguard": ("wireguard", "OBSERVED", 0),
    "openvpn": ("openvpn", "OBSERVED", 0),
    "gre": ("gre", "DATA", 1),
    "ipip": ("ip-in-ip", "DATA", 1),
    "ipcomp": ("ipcomp", "DATA", 0),
    "vxlan": ("vxlan", "DATA", 1),
}

_UDP_TUNNEL_PORTS = {
    500: "isakmp",
    4500: "isakmp",
    1194: "openvpn",
    4789: "vxlan",
    51820: "wireguard",
    8472: "vxlan",
}
_TCP_TUNNEL_PORTS = {1194: "openvpn"}


def _tunnel_entry(name: str) -> dict | None:
    entry = TUNNEL_KINDS.get(name)
    if entry is None:
        return None
    return {"protocol": entry[0], "state": entry[1], "inner_visible": entry[2]}


def detect_tunnel(
    packet: dict[str, Any], layers: list[str] | None = None
) -> dict | None:
    """Detect observable tunnel/VPN traffic from protocol chain and ports.

    Honesty rule: for encrypted tunnels (IPsec, WireGuard, OpenVPN) the inner
    traffic is not assumed visible; ``inner_visible`` is 0 for those.
    """
    candidates = [str(packet.get("app_proto") or "").lower()]
    candidates.append(str(packet.get("proto") or "").lower())
    candidates.extend(str(name).lower() for name in (layers or []))
    for name in candidates:
        entry = _tunnel_entry(name)
        if entry is not None:
            return entry
    proto = str(packet.get("proto") or "").lower()
    if proto == "udp":
        for port in (packet.get("sport"), packet.get("dport")):
            entry = _tunnel_entry(_UDP_TUNNEL_PORTS.get(_i(port), ""))
            if entry is not None:
                return entry
    if proto == "tcp":
        for port in (packet.get("sport"), packet.get("dport")):
            entry = _tunnel_entry(_TCP_TUNNEL_PORTS.get(_i(port), ""))
            if entry is not None:
                return entry
    return None


def _get(fields: dict[str, Any], *candidates: str) -> Any:
    for key in candidates:
        if key in fields:
            return fields[key]
    return None


def extract_dns(fields: dict[str, Any]) -> dict | None:
    qname = _s(_get(fields, "dns_dns_qry_name", "dns_qry_name"))
    if qname is None:
        return None
    is_response = _b(_get(fields, "dns_dns_flags_response", "dns_flags_response"))
    answers: list[str] = []
    for key in ("dns_dns_a", "dns_dns_aaaa"):
        answers.extend(_list(_get(fields, key)))
    cnames = _list(_get(fields, "dns_dns_cname", "dns_cname"))
    ttls = [
        number
        for number in (_i(item) for item in _list(_get(fields, "dns_dns_resp_ttl", "dns_resp_ttl")))
        if number is not None
    ]
    transaction_id = _i(_get(fields, "dns_dns_id", "dns_id"))
    return {
        "qname": qname,
        "qtype": qtype_name(_get(fields, "dns_dns_qry_type", "dns_qry_type")),
        "is_response": is_response,
        "rcode": rcode_name(_get(fields, "dns_dns_flags_rcode", "dns_flags_rcode"))
        if is_response
        else None,
        "answers": answers,
        "cnames": cnames,
        "ttl_min": min(ttls) if ttls else None,
        "transaction_id": transaction_id,
    }


SECURITY_HEADER_KEYS = {
    "strict-transport-security": "hsts",
    "content-security-policy": "csp",
    "x-content-type-options": "x_content_type_options",
    "x-frame-options": "x_frame_options",
    "referrer-policy": "referrer_policy",
    "permissions-policy": "permissions_policy",
}


def parse_set_cookie_metadata(header: str) -> dict | None:
    """Return cookie attributes without the value (values live in the vault)."""
    first, _, rest = str(header).partition(";")
    name, _, _value = first.partition("=")
    name = name.strip()
    if not name:
        return None
    attributes: dict[str, str | bool] = {}
    for chunk in rest.split(";"):
        part = chunk.strip()
        if not part:
            continue
        attr, _, value = part.partition("=")
        attr, value = attr.strip(), value.strip()
        lowered = attr.lower()
        if lowered in ("secure", "httponly"):
            attributes[lowered] = True
        elif lowered in ("samesite", "domain", "path", "expires", "max-age") and value:
            attributes[lowered] = value[:128]
    max_age: int | None = None
    try:
        if "max-age" in attributes:
            max_age = int(str(attributes["max-age"]))
    except ValueError:
        max_age = None
    return {
        "name": name[:128],
        "secure": bool(attributes.get("secure")),
        "http_only": bool(attributes.get("httponly")),
        "same_site": _s(attributes.get("samesite")),
        "domain": _s(attributes.get("domain")),
        "path": _s(attributes.get("path")),
        "max_age": max_age,
    }


def parse_security_headers(lines: list[str]) -> dict[str, Any]:
    flags: dict[str, Any] = {key: False for key in SECURITY_HEADER_KEYS.values()}
    flags["cache_control"] = None
    server = None
    for raw in lines:
        name, _, value = str(raw).partition(":")
        lowered = name.strip().lower()
        value = value.strip()
        if lowered in SECURITY_HEADER_KEYS:
            flags[SECURITY_HEADER_KEYS[lowered]] = True
        elif lowered == "cache-control" and value:
            flags["cache_control"] = value[:128]
        elif lowered == "server" and value:
            server = value[:128]
    flags["server"] = server
    return flags


def extract_http(fields: dict[str, Any], stream: str | None) -> dict | None:
    is_request = _b(_get(fields, "http_http_request", "http_request"))
    is_response = _b(_get(fields, "http_http_response", "http_response"))
    method = _s(_get(fields, "http_http_request_method", "http_request_method"))
    status = _i(_get(fields, "http_http_response_code", "http_response_code"))
    if not (is_request or is_response or method or status):
        return None
    uri = _get(fields, "http_http_request_uri", "http_request_uri")
    if uri is None:
        uri = _rebuild_without_query(
            _get(fields, "http_http_request_full_uri", "http_request_full_uri")
        )
    host = _s(_get(fields, "http_http_host", "http_host"))
    if host is None:
        full = _s(_get(fields, "http_http_request_full_uri", "http_request_full_uri"))
        if full:
            host = _s(urlsplit(full).hostname)
    path, query_names = sanitize_http_path(uri)
    auth = _s(_get(fields, "http_http_authorization", "http_authorization"))
    auth_scheme = _s(auth.split(" ", 1)[0]) if auth else None
    set_cookies = _list(_get(fields, "http_http_set_cookie", "http_set_cookie"))
    cookies = _list(_get(fields, "http_http_cookie", "http_cookie"))
    response_lines = _list(
        _get(fields, "http_http_response_line", "http_response_line")
    )
    security_headers = parse_security_headers(response_lines)
    cookie_metadata = [
        parsed
        for parsed in (parse_set_cookie_metadata(header) for header in set_cookies)
        if parsed is not None
    ]
    cookie_names = []
    for header in cookies:
        for chunk in str(header).split(";"):
            name = chunk.partition("=")[0].strip()
            if name:
                cookie_names.append(name[:128])
    return {
        "kind": "response" if (is_response and not is_request) else "request",
        "method": method,
        "host": host,
        "path": path,
        "query_names": query_names,
        "status": status,
        "version": _s(_get(fields, "http_http_request_version", "http_request_version")),
        "user_agent": _s(_get(fields, "http_http_user_agent", "http_user_agent")),
        "content_type": _s(_get(fields, "http_http_content_type", "http_content_type")),
        "server": _s(_get(fields, "http_http_server", "http_server")),
        "auth_scheme": auth_scheme,
        "set_cookie_count": len(set_cookies),
        "cookie_count": len(cookies),
        "set_cookies": cookie_metadata,
        "request_cookie_names": cookie_names[:32],
        "security_headers": security_headers,
        "stream": stream,
    }


def extract_tls(fields: dict[str, Any], stream: str | None) -> dict | None:
    handshake = _s(_get(fields, "tls_tls_handshake_type", "tls_handshake_type"))
    has_tls = any(key.startswith("tls_tls_") for key in fields)
    if not has_tls:
        return None
    kind = "other"
    if handshake == _TLS_HANDSHAKE_CLIENT_HELLO:
        kind = "client_hello"
    elif handshake == _TLS_HANDSHAKE_SERVER_HELLO:
        kind = "server_hello"
    elif handshake == _TLS_HANDSHAKE_CERTIFICATE:
        kind = "certificate"
    elif handshake:
        kind = "handshake_other"
    version = None
    if kind in ("client_hello", "server_hello"):
        version = _get(
            fields,
            "tls_tls_handshake_extensions_supported_version",
            "tls_handshake_extensions_supported_version",
        )
    if version is None:
        version = _get(fields, "tls_tls_handshake_version", "tls_handshake_version")
    validity: list[str] = []
    for key in ("x509af_x509af_utcTime", "x509af_x509af_generalizedTime"):
        validity.extend(_list(_get(fields, key)))
    cert_count = len(_list(_get(fields, "x509af_x509af_version"))) or None
    cipher_raw = (
        _s(_get(fields, "tls_tls_handshake_ciphersuite", "tls_handshake_ciphersuite"))
        if kind == "server_hello"
        else None
    )
    return {
        "kind": kind,
        "version": tls_version_name(version),
        "sni": _s(
            _get(
                fields,
                "tls_tls_handshake_extensions_server_name",
                "tls_handshake_extensions_server_name",
            )
        ),
        "alpn": ",".join(
            item
            for item in _list(
                _get(fields, "tls_tls_handshake_extensions_alpn_str", "tls_handshake_extensions_alpn_str")
            )
        )
        or None,
        "cipher": CIPHER_NAMES.get(cipher_raw, cipher_raw) if cipher_raw else None,
        "ja3": _s(_get(fields, "tls_tls_handshake_ja3_full", "tls_handshake_ja3_full")),
        "ja4": _s(_get(fields, "tls_tls_handshake_ja4", "tls_handshake_ja4")),
        "cert_count": cert_count,
        "cert_not_before": validity[0] if validity else None,
        "cert_not_after": validity[1] if len(validity) > 1 else None,
        "security": classify_security(
            "encrypted",
            "tls",
            version=tls_version_name(version),
            cipher=CIPHER_NAMES.get(cipher_raw, cipher_raw) if cipher_raw else None,
        ),
        "stream": stream,
    }


def enrich(fields: dict[str, Any], packet: dict[str, Any]) -> None:
    """Attach M3 enrichment keys to a normalized packet dict, in place."""
    packet["src_mac"] = _s(_get(fields, "eth_eth_src", "eth_src"))
    packet["dst_mac"] = _s(_get(fields, "eth_eth_dst", "eth_dst"))
    stream = _s(_get(fields, "tcp_tcp_stream", "tcp_stream")) or _s(
        _get(fields, "udp_udp_stream", "udp_stream")
    )
    packet["stream"] = stream

    proto = (packet.get("proto") or "").lower()
    app = app_protocol(proto)
    if proto == "dns":
        packet["dns"] = extract_dns(fields)
    elif proto == "http":
        packet["http"] = extract_http(fields, stream)
    elif proto == "tls":
        packet["tls"] = extract_tls(fields, stream)

    dns = packet.get("dns")
    http = packet.get("http")
    tls = packet.get("tls")
    if dns:
        packet["dns_qname"] = dns["qname"]
        packet["dns_qtype"] = dns["qtype"]
        packet["dns_rcode"] = dns["rcode"]
    if http:
        packet["http_host"] = http["host"]
        packet["http_method"] = http["method"]
        packet["http_status"] = http["status"]
        if http["host"] and not packet.get("dst"):
            pass
    if tls:
        packet["tls_sni"] = tls["sni"]
        packet["tls_version"] = tls["version"]

    packet["app_proto"] = app
    layers = packet.pop("_layers", None)
    packet["tunnel"] = detect_tunnel(packet, layers)
    packet["encryption"] = classify_encryption(proto, app)
    packet["security"] = classify_security(
        packet["encryption"],
        app,
        version=(tls or {}).get("version"),
        cipher=(tls or {}).get("cipher"),
    )
