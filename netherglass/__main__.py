"""Netherglass command line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .config import CAPTURE_PROFILES, AppConfig, ensure_layout
from .interfaces import capture_readiness, discover_interfaces
from .security.audit import append_event
from .security.auth import create_user
from .security.rbac import ROLE_PERMISSIONS
from .store.db import Database


def _load_config(args) -> AppConfig:
    data_dir = Path(args.data_dir).expanduser() if args.data_dir else None
    return AppConfig.load(data_dir)


def cmd_serve(args) -> int:
    from .api.app import create_app
    from .logging_setup import setup_logging

    config = _load_config(args)
    if args.host:
        config.serve.host = args.host
    if args.port:
        config.serve.port = args.port
    if args.profile:
        config.profile = args.profile
    try:
        config.validate()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ensure_layout(config.data_dir)
    setup_logging(config.data_dir / "logs")
    for warning in config.warnings():
        print(f"[warning] {warning}")

    app = create_app(config)
    creds_path = config.data_dir / "BOOTSTRAP_CREDENTIALS.txt"
    if creds_path.exists():
        print(f"[bootstrap] initial admin credentials written to: {creds_path}")

    import uvicorn

    print(f"[netherglass] serving on http://{config.serve.host}:{config.serve.port}")
    uvicorn.run(app, host=config.serve.host, port=config.serve.port, log_level="info")
    return 0


def cmd_interfaces(args) -> int:
    interfaces = discover_interfaces()
    if args.json:
        print(json.dumps({"interfaces": [asdict(i) for i in interfaces]}, indent=2))
        return 0
    print(f"{'NAME':<12} {'KIND':<9} {'STATE':<9} ADDRESSES")
    for info in interfaces:
        addresses = ", ".join(info.addresses) or "-"
        print(f"{info.name:<12} {info.kind:<9} {info.operstate:<9} {addresses}")
    notes = sorted({i.notes for i in interfaces if i.notes})
    if notes:
        print()
        for note in notes:
            print(f"note: {note}")
    return 0


def cmd_doctor(args) -> int:
    config = _load_config(args)
    print(f"netherglass {__version__}")
    print(f"data dir: {config.data_dir}")
    profile = CAPTURE_PROFILES[config.profile]
    print(f"profile:  {config.profile} ({profile.name})")
    report = capture_readiness()
    print("\ncapture sources:")
    for source in report["sources"]:
        mark = "OK" if source["available"] else "--"
        print(f"  [{mark}] {source['id']:<8} {source['detail']}")
    if report["hints"]:
        print("\nhints:")
        for hint in report["hints"]:
            print(f"  {hint}")
    warnings = config.warnings()
    if warnings:
        print("\nwarnings:")
        for warning in warnings:
            print(f"  {warning}")
    return 0


def cmd_user_add(args) -> int:
    config = _load_config(args)
    ensure_layout(config.data_dir)
    db = Database(config.db_path())
    db.migrate()
    if args.role not in ROLE_PERMISSIONS:
        print(f"error: unknown role '{args.role}'", file=sys.stderr)
        return 2
    password = getpass.getpass("password: ")
    confirm = getpass.getpass("confirm password: ")
    if password != confirm:
        print("error: passwords do not match", file=sys.stderr)
        return 2
    if len(password) < 10:
        print("error: password must be at least 10 characters", file=sys.stderr)
        return 2
    with db.connect() as conn:
        try:
            create_user(conn, args.username, password, args.role)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        append_event(
            conn,
            actor=args.actor,
            action="USER_CREATED",
            target=args.username,
            details={"role": args.role},
        )
    print(f"user '{args.username}' created with role '{args.role}'")
    return 0


def cmd_user_list(args) -> int:
    config = _load_config(args)
    db = Database(config.db_path())
    db.migrate()
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT username, role, disabled, created_at FROM users ORDER BY username"
        ).fetchall()
    print(f"{'USERNAME':<20} {'ROLE':<8} {'STATE':<9} CREATED")
    for row in rows:
        state = "disabled" if row["disabled"] else "active"
        print(f"{row['username']:<20} {row['role']:<8} {state:<9} {row['created_at']}")
    return 0


def cmd_capture(args) -> int:
    import time

    from .capture.engine import CaptureEngine, CaptureError
    from .emergency import EmergencyStop

    config = _load_config(args)
    ensure_layout(config.data_dir)
    db = Database(config.db_path())
    db.migrate()
    emergency = EmergencyStop(db)
    engine = CaptureEngine(config, db, emergency)
    try:
        started = engine.start_live(
            args.interface,
            actor="cli",
            bpf=args.bpf,
            chunk_seconds=args.chunk,
        )
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"capture {started['capture_id']} running on {started['interface']} "
        f"via {started['source']} (chunk {args.chunk}s)"
    )
    if started.get("bpf"):
        print(f"bpf filter: {started['bpf']}")
    deadline = time.monotonic() + args.seconds
    try:
        while time.monotonic() < deadline:
            time.sleep(1)
            status = engine.status()
            if not status.get("active"):
                break
            print(
                f"  captured={status.get('packets_captured', 0)} "
                f"dropped={status.get('packets_dropped', 0)} "
                f"decoded={status.get('packets_decoded', 0)} "
                f"decode_drops={status.get('decode_drops', 0)} "
                f"queue={status.get('queue_depth', 0)} "
                f"bytes={status.get('bytes_written', 0)}"
            )
    except KeyboardInterrupt:
        pass
    finally:
        status = engine.status()
        if status.get("active"):
            summary = engine.stop(actor="cli", reason=f"cli run ({args.seconds}s)")
            print(
                f"stopped: captured={summary['packets_captured']} "
                f"dropped={summary['packets_dropped']} "
                f"decoded={summary['packets_decoded']} "
                f"decode_drops={summary['decode_drops']} "
                f"files={summary['files']} bytes={summary['total_bytes']}"
            )
        elif status.get("last_capture"):
            last = status["last_capture"]
            print(
                f"capture ended: status={last['status']} "
                f"packets_captured={last['packets_captured']} "
                f"error={last.get('error') or '-'}"
            )
    return 0


def cmd_import(args) -> int:
    import time

    from .capture.engine import CaptureEngine, CaptureError
    from .emergency import EmergencyStop

    config = _load_config(args)
    ensure_layout(config.data_dir)
    db = Database(config.db_path())
    db.migrate()
    engine = CaptureEngine(config, db, EmergencyStop(db))
    try:
        result = engine.import_file(args.file, actor="cli")
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"importing {args.file} as {result['capture_id']} (sha256 {result['sha256'][:16]}...)")
    for _ in range(1200):
        with db.connect() as conn:
            from .store import packets as packets_store

            row = packets_store.get_capture(conn, result["capture_id"])
        if row and row["status"] != "decoding":
            print(
                f"status={row['status']} decoded_packets={row['packets_captured']} "
                f"decode_drops={row['decode_drops']} error={row['error'] or '-'}"
            )
            return 0 if row["status"] == "ready" else 1
        time.sleep(0.5)
    print("timed out waiting for decode", file=sys.stderr)
    return 1


def _open_analysis(args):
    from .store.db import Database

    config = _load_config(args)
    ensure_layout(config.data_dir)
    db = Database(config.db_path())
    db.migrate()
    return config, db


def _resolve_capture(conn, capture_id: str | None) -> str:
    from .store import packets as packets_store

    if capture_id:
        row = packets_store.get_capture(conn, capture_id)
        if row is None:
            raise SystemExit(f"error: capture {capture_id!r} not found")
        return capture_id
    rows = packets_store.list_captures(conn, limit=1)
    if not rows:
        raise SystemExit("error: no captures found; run 'netherglass import <file>' first")
    return rows[0]["id"]


def cmd_hosts(args) -> int:
    import json

    from .store import analysis as analysis_store

    _, db = _open_analysis(args)
    with db.connect() as conn:
        capture_id = _resolve_capture(conn, args.capture)
        hosts = analysis_store.list_hosts(conn, capture_id, limit=args.limit)
    if args.json:
        print(json.dumps({"capture_id": capture_id, "hosts": hosts}, indent=2))
        return 0
    print(f"capture {capture_id}: {len(hosts)} hosts")
    print(f"{'IP':<24} {'HOSTNAME':<32} {'PACKETS':>8} {'BYTES':>9}  SOURCE")
    for host in hosts:
        print(
            f"{host['ip']:<24} {(host['hostname'] or '-'):<32} "
            f"{host['packets']:>8} {host['bytes']:>9}  {host['hostname_source'] or '-'}"
        )
    return 0


def cmd_stats(args) -> int:
    import json

    from .store import analysis as analysis_store

    _, db = _open_analysis(args)
    with db.connect() as conn:
        capture_id = _resolve_capture(conn, args.capture)
        data = analysis_store.stats(conn, capture_id)
    if args.json:
        print(json.dumps({"capture_id": capture_id, **data}, indent=2))
        return 0
    print(f"capture {capture_id} statistics")

    def _section(title: str, rows: list[dict], columns: list[str]) -> None:
        print(f"\n{title}")
        for row in rows:
            cells = " ".join(str(row.get(col) or "-") for col in columns)
            print(f"  {cells}")

    summary = data.get("dns_summary") or {}
    print(
        f"dns: queries={summary.get('queries') or 0} "
        f"nxdomain={summary.get('nxdomain') or 0} "
        f"orphan_responses={summary.get('orphan_responses') or 0}"
    )
    _section("top talkers", data["top_talkers"], ["ip", "hostname", "packets", "bytes"])
    _section("top destinations", data["top_destinations"], ["ip", "packets", "bytes"])
    _section("top domains", data["top_domains"], ["qname", "queries", "nxdomain"])
    _section("top ports", data["top_ports"], ["port", "proto", "packets", "bytes"])
    _section("protocols", data["top_protocols"], ["protocol", "packets", "bytes"])
    _section("tls versions", data["tls_versions"], ["version", "sessions"])
    _section("encryption", data["encryption"], ["encryption", "packets", "bytes"])
    print(f"\nfindings: {data['findings']['note']}")
    print(f"sensitive data: {data['sensitive_data']['note']}")
    return 0


def cmd_search(args) -> int:
    import json

    from .analysis.query import QueryError, compile_query
    from .store import packets as packets_store

    _, db = _open_analysis(args)
    try:
        where_sql, params = compile_query(args.query)
    except QueryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    with db.connect() as conn:
        capture_id = _resolve_capture(conn, args.capture)
        result = packets_store.search_packets(
            conn, capture_id, where_sql, params, limit=args.limit, offset=0
        )
    if args.json:
        print(json.dumps({"capture_id": capture_id, **result}, indent=2))
        return 0
    print(
        f"capture {capture_id}: {result['total']} packet(s) match "
        f"(showing {len(result['packets'])})"
    )
    for packet in result["packets"]:
        proto = packet["app_proto"] or packet["proto"] or "?"
        print(
            f"  #{packet['num']:<6} {packet['ts'] if packet['ts'] is not None else '-'}  "
            f"{packet['src']}:{packet['sport']} -> {packet['dst']}:{packet['dport']}  "
            f"{proto}  {packet['info'] or ''}"
        )
    return 0


def cmd_panic(args) -> int:
    from .emergency import EmergencyStop

    config = _load_config(args)
    ensure_layout(config.data_dir)
    db = Database(config.db_path())
    db.migrate()
    estop = EmergencyStop(db)
    if estop.is_stopped():
        print("emergency security stop is already active")
        return 0
    actor = args.actor or f"cli:{getpass.getuser()}"
    status = estop.trigger(actor=actor, reason=args.reason)
    print(f"emergency security stop active (actor={actor})")
    for key, value in status.items():
        print(f"  {key}: {value}")
    print("recovery requires an authorized operator in the web UI")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netherglass",
        description="Network visibility, evidence preservation and authorized "
        "security-testing platform. Internal use only.",
    )
    parser.add_argument(
        "--version", action="version", version=f"netherglass {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the web application")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.add_argument("--profile", choices=["A", "B", "C"])
    serve.add_argument("--data-dir")
    serve.set_defaults(func=cmd_serve)

    ifaces = sub.add_parser("interfaces", help="list network interfaces")
    ifaces.add_argument("--json", action="store_true")
    ifaces.add_argument("--data-dir")
    ifaces.set_defaults(func=cmd_interfaces)

    doctor = sub.add_parser("doctor", help="environment and readiness checks")
    doctor.add_argument("--data-dir")
    doctor.set_defaults(func=cmd_doctor)

    capture = sub.add_parser("capture", help="run a headless live capture")
    capture.add_argument("--interface", required=True)
    capture.add_argument("--bpf", default=None, help="additional BPF filter")
    capture.add_argument("--seconds", type=int, default=15)
    capture.add_argument("--chunk", type=int, default=5, help="ring chunk seconds")
    capture.add_argument("--data-dir")
    capture.set_defaults(func=cmd_capture)

    imp = sub.add_parser("import", help="import an offline PCAP/PCAPNG file")
    imp.add_argument("file")
    imp.add_argument("--data-dir")
    imp.set_defaults(func=cmd_import)

    hosts = sub.add_parser("hosts", help="list discovered hosts")
    hosts.add_argument("capture", nargs="?", default=None, help="capture id (default: latest)")
    hosts.add_argument("--limit", type=int, default=200)
    hosts.add_argument("--json", action="store_true")
    hosts.add_argument("--data-dir")
    hosts.set_defaults(func=cmd_hosts)

    stats = sub.add_parser("stats", help="capture statistics")
    stats.add_argument("capture", nargs="?", default=None, help="capture id (default: latest)")
    stats.add_argument("--json", action="store_true")
    stats.add_argument("--data-dir")
    stats.set_defaults(func=cmd_stats)

    search = sub.add_parser("search", help="search packets with the query language")
    search.add_argument("query", help='e.g. \'tls.sni ~ "example" AND port = 443\'')
    search.add_argument("capture", nargs="?", default=None, help="capture id (default: latest)")
    search.add_argument("--limit", type=int, default=100)
    search.add_argument("--json", action="store_true")
    search.add_argument("--data-dir")
    search.set_defaults(func=cmd_search)

    user = sub.add_parser("user", help="user management")
    user_sub = user.add_subparsers(dest="user_command", required=True)
    user_add = user_sub.add_parser("add")
    user_add.add_argument("--username", required=True)
    user_add.add_argument("--role", default="analyst")
    user_add.add_argument("--actor", default="cli")
    user_add.add_argument("--data-dir")
    user_add.set_defaults(func=cmd_user_add)
    user_list = user_sub.add_parser("list")
    user_list.add_argument("--data-dir")
    user_list.set_defaults(func=cmd_user_list)

    panic = sub.add_parser(
        "panic",
        help="out-of-band emergency security stop (works without the web UI)",
    )
    panic.add_argument("--reason", required=True, help="audited reason for the stop")
    panic.add_argument("--actor", default=None, help="default: cli:<os user>")
    panic.add_argument("--data-dir")
    panic.set_defaults(func=cmd_panic)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
