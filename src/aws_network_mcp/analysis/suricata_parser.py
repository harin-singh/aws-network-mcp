"""Parse common AWS Network Firewall Suricata / 5-tuple rule shapes."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, cast

from aws_network_mcp.models import FirewallRule

DEFAULT_HOME_NET = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

_SUPPORTED_ACTIONS = {"pass", "drop", "reject"}
_SUPPORTED_PROTOCOLS = {"ip", "tcp", "udp", "icmp", "any", "-1"}
_SUPPORTED_OPTIONS = {
    "sid",
    "msg",
    "rev",
    "classtype",
    "metadata",
    "priority",
    "reference",
    "gid",
}
_UNSUPPORTED_OPTION_HINTS = (
    "content",
    "pcre",
    "flow",
    "flowbits",
    "threshold",
    "detection_filter",
    "byte_test",
    "byte_jump",
    "byte_extract",
    "isdataat",
    "dsize",
    "itype",
    "icode",
    "icmp_id",
    "window",
    "flags",
    "ttl",
    "tos",
    "seq",
    "ack",
    "http.",
    "http_",
    "tls.",
    "ssl_",
    "dns.",
    "ssh.",
    "ja3",
    "fileinfo",
    "filename",
    "xbits",
    "dataset",
    "geoip",
    "iprep",
    "app-layer",
    "stream",
    "urilen",
    "lua",
)

_RULE_RE = re.compile(
    r"^(?P<action>pass|drop|reject|alert)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<src>\S+|\[[^\]]+\])\s+"
    r"(?P<sport>\S+)\s+"
    r"(?P<dir>->|<>)\s+"
    r"(?P<dst>\S+|\[[^\]]+\])\s+"
    r"(?P<dport>\S+)\s*"
    r"(?:\((?P<opts>.*)\))?\s*$",
    re.IGNORECASE,
)


@dataclass
class ParseResult:
    """Rules that could be evaluated plus skipped-feature notes."""

    rules: list[FirewallRule] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)


def parse_suricata_rules(
    rules_string: str,
    *,
    home_net: tuple[str, ...] = DEFAULT_HOME_NET,
    source_name: str = "RulesString",
) -> ParseResult:
    """Parse a Suricata rules blob into first-match FirewallRule objects."""
    result = ParseResult()
    for line_no, raw in enumerate(rules_string.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parsed = _parse_line(line, home_net=home_net)
        if parsed is None:
            result.unsupported.append(
                f"{source_name}:{line_no}: unrecognized Suricata header (not a 5-tuple pass/drop rule)"
            )
            continue
        rule, notes = parsed
        if rule is None:
            result.unsupported.extend(f"{source_name}:{line_no}: {note}" for note in notes)
            continue
        result.unsupported.extend(f"{source_name}:{line_no}: {note}" for note in notes)
        result.rules.append(rule)
    return result


def parse_stateful_5tuple_rules(
    stateful_rules: list[dict[str, object]],
    *,
    home_net: tuple[str, ...] = DEFAULT_HOME_NET,
    source_name: str = "StatefulRules",
) -> ParseResult:
    """Parse Network Firewall StatefulRules 5-tuple objects."""
    result = ParseResult()
    for index, raw in enumerate(stateful_rules, start=1):
        if not isinstance(raw, dict):
            result.unsupported.append(f"{source_name}[{index}]: not an object")
            continue
        action = str(raw.get("Action", "")).lower()
        if action == "reject":
            action = "drop"
        if action == "alert":
            result.unsupported.append(
                f"{source_name}[{index}]: alert action is not evaluated for allow/deny"
            )
            continue
        if action not in {"pass", "drop"}:
            result.unsupported.append(f"{source_name}[{index}]: unsupported action {action!r}")
            continue
        header = raw.get("Header")
        if not isinstance(header, dict):
            result.unsupported.append(f"{source_name}[{index}]: missing Header")
            continue
        protocol = str(header.get("Protocol", "IP")).lower()
        if protocol not in _SUPPORTED_PROTOCOLS:
            result.unsupported.append(f"{source_name}[{index}]: unsupported protocol {protocol!r}")
            continue
        src, src_neg, src_note = _expand_address(str(header.get("Source", "ANY")), home_net)
        dst, dst_neg, dst_note = _expand_address(str(header.get("Destination", "ANY")), home_net)
        notes = [n for n in (src_note, dst_note) if n]
        sid, message = _options_from_stateful(raw.get("RuleOptions"))
        dest_ports = _normalize_port(str(header.get("DestinationPort", "ANY")))
        result.rules.append(
            FirewallRule(
                sid=sid or str(index),
                action=cast(Literal["pass", "drop"], action),
                protocol=protocol,
                source_cidrs=src,
                dest_cidrs=dst,
                dest_negate=dst_neg,
                source_negate=src_neg,
                dest_ports=dest_ports,
                message=message,
            )
        )
        result.unsupported.extend(f"{source_name}[{index}]: {note}" for note in notes)
    return result


def _parse_line(
    line: str, *, home_net: tuple[str, ...]
) -> tuple[FirewallRule | None, list[str]] | None:
    match = _RULE_RE.match(line.rstrip(";"))
    if not match:
        return None
    action = match.group("action").lower()
    notes: list[str] = []
    if action == "alert":
        return None, ["alert action is not evaluated for allow/deny"]
    if action == "reject":
        action = "drop"
    if action not in _SUPPORTED_ACTIONS:
        return None, [f"unsupported action {action!r}"]

    protocol = match.group("proto").lower()
    if protocol not in _SUPPORTED_PROTOCOLS:
        return None, [f"unsupported protocol {protocol!r} (http/tls/dns inspectors are skipped)"]

    src, src_neg, src_note = _expand_address(match.group("src"), home_net)
    dst, dst_neg, dst_note = _expand_address(match.group("dst"), home_net)
    if src_note:
        notes.append(src_note)
    if dst_note:
        notes.append(dst_note)

    options, option_notes = _parse_options(match.group("opts") or "")
    notes.extend(option_notes)
    if any(note.startswith("skipped:") for note in option_notes):
        return None, notes

    return (
        FirewallRule(
            sid=options.get("sid", "unknown"),
            action=cast(Literal["pass", "drop"], action),
            protocol=protocol,
            source_cidrs=src,
            dest_cidrs=dst,
            dest_negate=dst_neg,
            source_negate=src_neg,
            dest_ports=_normalize_port(match.group("dport")),
            message=options.get("msg", ""),
        ),
        notes,
    )


def _expand_address(
    token: str, home_net: tuple[str, ...]
) -> tuple[tuple[str, ...], bool, str | None]:
    raw = token.strip()
    negate = raw.startswith("!")
    if negate:
        raw = raw[1:]
    raw = raw.strip()
    if raw.upper() == "ANY":
        return ("0.0.0.0/0",), negate, None
    if raw.upper() == "$HOME_NET":
        return home_net, negate, None
    if raw.startswith("[") and raw.endswith("]"):
        parts = tuple(part.strip() for part in raw[1:-1].split(",") if part.strip())
        cidrs: list[str] = []
        for part in parts:
            expanded, part_neg, note = _expand_address(part, home_net)
            if part_neg or note:
                return (
                    expanded,
                    negate,
                    note or "per-item negation inside a list is not supported; list used as-is",
                )
            cidrs.extend(expanded)
        return tuple(cidrs), negate, None
    if raw.startswith("$"):
        return (raw,), negate, f"unsupported variable {raw} (only $HOME_NET is expanded)"
    return (raw,), negate, None


def _normalize_port(token: str) -> tuple[str, ...]:
    raw = token.strip()
    if raw.lower() == "any":
        return ("any",)
    if raw.startswith("[") and raw.endswith("]"):
        return tuple(part.strip() for part in raw[1:-1].split(",") if part.strip()) or ("any",)
    return (raw,)


def _parse_options(body: str) -> tuple[dict[str, str], list[str]]:
    options: dict[str, str] = {}
    notes: list[str] = []
    for chunk in body.split(";"):
        item = chunk.strip()
        if not item:
            continue
        if ":" in item:
            key, value = item.split(":", 1)
        else:
            key, value = item, ""
        key = key.strip().lower()
        value = value.strip().strip('"')
        if key in _SUPPORTED_OPTIONS:
            options[key] = value
            continue
        if any(key.startswith(hint) or hint in key for hint in _UNSUPPORTED_OPTION_HINTS):
            notes.append(
                f"skipped: unsupported Suricata option {key!r} "
                f"(content/pcre/flow/http/tls/byte_* inspectors are not evaluated)"
            )
            continue
        notes.append(f"ignored unknown option {key!r}")
    return options, notes


def _options_from_stateful(raw: object) -> tuple[str, str]:
    sid = ""
    message = ""
    if not isinstance(raw, list):
        return sid, message
    for item in raw:
        if not isinstance(item, dict):
            continue
        keyword = str(item.get("Keyword", "")).lower()
        settings = item.get("Settings")
        value = ""
        if isinstance(settings, list) and settings:
            value = str(settings[0])
        if keyword == "sid":
            sid = value
        elif keyword == "msg":
            message = value.strip('"')
    return sid, message
