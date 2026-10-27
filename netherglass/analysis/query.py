"""Text query language for packet search (spec section 38).

Grammar (precedence: NOT > AND > OR):

    expr    := term (OR term)*
    term    := factor (AND factor)*
    factor  := NOT factor | "(" expr ")" | comparison
    compare := FIELD OP VALUE
    OP      := == | = | != | > | >= | < | <= | contains | startswith | endswith
    VALUE   := "quoted" | number | bare

Example: src.ip == "10.0.0.25" AND dst.port == 443 AND dns.name contains "example.com"

The compiler emits a parameterized SQL fragment over the packets table. Fields
that belong to later phases (sensitive_data.*, finding.severity) are rejected
with an explicit message rather than silently ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


class QueryError(ValueError):
    pass


@dataclass(frozen=True)
class FieldSpec:
    columns: tuple[str, ...]
    kind: str  # "text" | "number"
    label: str

    def sql(self, op: str, value: str) -> tuple[str, list]:
        if self.kind == "number":
            try:
                number: float | int = float(value)
                if number.is_integer():
                    number = int(number)
            except ValueError as exc:
                raise QueryError(f"{self.label} expects a number, got {value!r}") from exc
            sql_op = {
                "==": "=",
                "=": "=",
                "!=": "!=",
                ">": ">",
                ">=": ">=",
                "<": "<",
                "<=": "<=",
            }.get(op)
            if sql_op is None:
                raise QueryError(f"operator {op!r} is not valid for {self.label}")
            expressions = [f"{column} {sql_op} ?" for column in self.columns]
            params = [number] * len(self.columns)
            return _combine(expressions), params

        if op not in ("==", "=", "!=", "contains", "startswith", "endswith"):
            raise QueryError(f"operator {op!r} is not valid for {self.label}")
        escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        expressions = []
        for column in self.columns:
            lowered = f"LOWER({column})"
            if op in ("==", "="):
                expressions.append(f"{lowered} = LOWER(?)")
            elif op == "!=":
                expressions.append(f"{lowered} != LOWER(?)")
            elif op == "contains":
                expressions.append(f"{lowered} LIKE LOWER(?) ESCAPE '\\'")
            elif op == "startswith":
                expressions.append(f"{lowered} LIKE LOWER(?) ESCAPE '\\'")
            else:
                expressions.append(f"{lowered} LIKE LOWER(?) ESCAPE '\\'")
        if op in ("==", "=", "!="):
            compare = value
        elif op == "contains":
            compare = f"%{escaped}%"
        elif op == "startswith":
            compare = f"{escaped}%"
        else:
            compare = f"%{escaped}"
        return _combine(expressions), [compare] * len(self.columns)


def _combine(expressions: list[str]) -> str:
    if len(expressions) == 1:
        return expressions[0]
    return "(" + " OR ".join(expressions) + ")"


FIELDS: dict[str, FieldSpec] = {
    "src.ip": FieldSpec(("src",), "text", "src.ip"),
    "src": FieldSpec(("src",), "text", "src"),
    "dst.ip": FieldSpec(("dst",), "text", "dst.ip"),
    "dst": FieldSpec(("dst",), "text", "dst"),
    "ip": FieldSpec(("src", "dst"), "text", "ip"),
    "host": FieldSpec(("src", "dst"), "text", "host"),
    "mac": FieldSpec(("src_mac", "dst_mac"), "text", "mac"),
    "src.port": FieldSpec(("sport",), "number", "src.port"),
    "dst.port": FieldSpec(("dport",), "number", "dst.port"),
    "port": FieldSpec(("sport", "dport"), "number", "port"),
    "protocol": FieldSpec(("COALESCE(app_proto, proto)",), "text", "protocol"),
    "proto": FieldSpec(("COALESCE(app_proto, proto)",), "text", "proto"),
    "app.proto": FieldSpec(("app_proto",), "text", "app.proto"),
    "encryption": FieldSpec(("encryption",), "text", "encryption"),
    "security": FieldSpec(("security",), "text", "security"),
    "dns.name": FieldSpec(("dns_qname",), "text", "dns.name"),
    "dns.qtype": FieldSpec(("dns_qtype",), "text", "dns.qtype"),
    "dns.rcode": FieldSpec(("dns_rcode",), "text", "dns.rcode"),
    "tls.sni": FieldSpec(("tls_sni",), "text", "tls.sni"),
    "tls.version": FieldSpec(("tls_version",), "text", "tls.version"),
    "http.host": FieldSpec(("http_host",), "text", "http.host"),
    "http.method": FieldSpec(("http_method",), "text", "http.method"),
    "http.status": FieldSpec(("http_status",), "number", "http.status"),
    "stream": FieldSpec(("stream",), "number", "stream"),
}

DEFERRED_FIELDS = {
    "sensitive_data.detected": "not part of the packet search index — see the EVIDENCE tab",
    "sensitive_data.type": "not part of the packet search index — see the EVIDENCE tab",
    "finding.severity": "not part of the packet search index — see the FINDINGS tab",
}

AVAILABLE_FIELDS = sorted(FIELDS)

_TOKEN = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<op>==|!=|>=|<=|~|=|>|<)
  | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<word>[A-Za-z_][A-Za-z0-9_.]*)
    """,
    re.VERBOSE,
)

KEYWORDS = {"and", "or", "not", "contains", "startswith", "endswith"}


@dataclass
class _Token:
    kind: str
    value: str
    pos: int


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    index = 0
    while index < len(text):
        match = _TOKEN.match(text, index)
        if not match:
            raise QueryError(f"unexpected character {text[index]!r} at position {index}")
        index = match.end()
        if match.lastgroup == "space":
            continue
        kind = match.lastgroup or "word"
        value = match.group()
        if kind == "string":
            value = value[1:-1].replace('\\"', '"').replace("\\'", "'")
        elif kind == "word" and value.lower() in KEYWORDS:
            kind = value.lower()
        tokens.append(_Token(kind, value, match.start()))
    return tokens


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.index = 0

    def peek(self) -> _Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def next(self) -> _Token:
        token = self.peek()
        if token is None:
            raise QueryError("unexpected end of query")
        self.index += 1
        return token

    def parse(self) -> tuple[str, list]:
        if not self.tokens:
            raise QueryError("empty query")
        sql, params = self.parse_or()
        leftover = self.peek()
        if leftover is not None:
            raise QueryError(f"unexpected token {leftover.value!r} at position {leftover.pos}")
        return sql, params

    def parse_or(self) -> tuple[str, list]:
        sql, params = self.parse_and()
        while self.peek() is not None and self.peek().kind == "or":
            self.next()
            right, right_params = self.parse_and()
            sql = f"({sql} OR {right})"
            params.extend(right_params)
        return sql, params

    def parse_and(self) -> tuple[str, list]:
        sql, params = self.parse_factor()
        while self.peek() is not None and self.peek().kind == "and":
            self.next()
            right, right_params = self.parse_factor()
            sql = f"({sql} AND {right})"
            params.extend(right_params)
        return sql, params

    def parse_factor(self) -> tuple[str, list]:
        token = self.peek()
        if token is None:
            raise QueryError("unexpected end of query")
        if token.kind == "not":
            self.next()
            sql, params = self.parse_factor()
            return f"(NOT {sql})", params
        if token.kind == "lparen":
            self.next()
            sql, params = self.parse_or()
            closing = self.peek()
            if closing is None or closing.kind != "rparen":
                raise QueryError("missing closing parenthesis")
            self.next()
            return f"({sql})", params
        return self.parse_comparison()

    def parse_comparison(self) -> tuple[str, list]:
        field_token = self.next()
        if field_token.kind != "word":
            raise QueryError(
                f"expected a field name, got {field_token.value!r} at position {field_token.pos}"
            )
        field = field_token.value.lower()
        if field in DEFERRED_FIELDS:
            raise QueryError(f"field {field} is not available yet: {DEFERRED_FIELDS[field]}")
        spec = FIELDS.get(field)
        if spec is None:
            raise QueryError(
                f"unknown field {field!r}; available: {', '.join(AVAILABLE_FIELDS)}"
            )
        op_token = self.next()
        if op_token.kind in ("contains", "startswith", "endswith"):
            op = op_token.kind
        elif op_token.kind == "op":
            op = "contains" if op_token.value == "~" else op_token.value
        else:
            raise QueryError(
                f"expected an operator after {field}, got {op_token.value!r} "
                f"at position {op_token.pos}"
            )
        value_token = self.next()
        if value_token.kind not in ("string", "number", "word"):
            raise QueryError(
                f"expected a value, got {value_token.value!r} at position {value_token.pos}"
            )
        if value_token.kind == "word" and value_token.value.lower() in ("true", "false"):
            raise QueryError(
                f"boolean values are not supported for {field}; boolean fields arrive with M4"
            )
        return spec.sql(op, value_token.value)


def compile_query(text: str) -> tuple[str, list]:
    return _Parser(_tokenize(text)).parse()
