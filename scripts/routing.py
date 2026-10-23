"""Normalized routing records and dependency-free V2Ray protobuf support."""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

FIELDS = ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr")
DOMAIN_FIELDS = FIELDS[:-1]
DOMAIN_TYPES = {0: "domain_keyword", 1: "domain_regex", 2: "domain_suffix", 3: "domain"}


def empty():
    return {key: set() for key in FIELDS}


def merge(*records):
    result = empty()
    for record in records:
        for key in FIELDS:
            result[key].update(record.get(key, ()))
    return result


def normalized_domain(value):
    value = value.strip().rstrip(".").lstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if not value or any(c in value for c in "/:@ \t\r\n"):
        raise ValueError(f"Invalid domain: {value!r}")
    # Normalize IDNs without lowercasing regular expressions or keywords.
    value = value.encode("idna").decode("ascii").lower()
    if len(value) > 253 or any(not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label)
                               for label in value.split(".")):
        raise ValueError(f"Invalid DNS name: {value!r}")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError(f"IP address in domain input: {value}")


def add(record, key, value):
    if key not in FIELDS:
        raise ValueError(f"Unknown rule field: {key}")
    if not isinstance(value, str) or not value:
        raise ValueError("Empty or non-string rule")
    if key in ("domain", "domain_suffix"):
        value = normalized_domain(value)
    elif key == "domain_regex":
        # Compilation against the target engine happens before publishing SRS.
        re.compile(value)
    elif key == "ip_cidr":
        net = ipaddress.ip_network(value, strict=False)
        if (not net.network_address.is_global or net.network_address.is_multicast
                or net.network_address.is_reserved or not net.broadcast_address.is_global):
            raise ValueError(f"Non-public network in imported routing data: {net}")
        value = str(net)
    record[key].add(value)


def count(record):
    return sum(len(record.get(key, ())) for key in FIELDS)


def serial(record):
    return {key: sorted(record.get(key, ())) for key in FIELDS if record.get(key)}


def parse_text(text, family="domains", allow_empty=False, max_invalid=0, quarantine=None):
    record = empty()
    bad = []
    prefixes = {"full": "domain", "domain": "domain_suffix", "keyword": "domain_keyword",
                "regexp": "domain_regex", "regex": "domain_regex"}
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip().lstrip("\ufeff")
        if not line or line.startswith(("#", "//")):
            continue
        try:
            if family == "ips":
                if line.startswith(("ip:", "cidr:")):
                    line = line.split(":", 1)[1]
                add(record, "ip_cidr", line)
            else:
                if family == "mixed":
                    line = line.strip('"')
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                    except ValueError:
                        pass
                    else:
                        add(record, "ip_cidr", str(network))
                        continue
                prefix, separator, tail = line.partition(":")
                key = prefixes.get(prefix, "domain_suffix")
                value = tail if separator and prefix in prefixes else line
                if family == "mixed" and key in ("domain", "domain_suffix"):
                    value = normalized_domain(value)
                    if "." not in value:
                        raise ValueError(f"Single-label name in mixed source: {value!r}")
                add(record, key, value)
        except (ValueError, UnicodeError, re.error) as exc:
            bad.append(f"line {line_no}: {exc}")
    if quarantine is not None:
        quarantine.update({"invalid_count": len(bad), "invalid_examples": bad[:20]})
    if bad and (len(bad) > max_invalid or len(bad) / max(1, len(text.splitlines())) > 0.001):
        raise ValueError("Malformed source: " + "; ".join(bad[:5]) + f" ({len(bad)} invalid lines)")
    if not allow_empty and not count(record):
        raise ValueError("Empty source")
    return record


def parse_json(text):
    obj = json.loads(text)
    if not isinstance(obj, dict) or not isinstance(obj.get("rules"), list):
        raise ValueError("Expected sing-box source rule-set")
    record = empty()
    for rule in obj["rules"]:
        if not isinstance(rule, dict) or set(rule) - set(FIELDS):
            raise ValueError("Unsupported fields/logical rule; refusing lossy import")
        for key, values in rule.items():
            for value in values if isinstance(values, list) else [values]:
                add(record, key, value)
    if not count(record):
        raise ValueError("Empty JSON source")
    return record


def varint(number):
    result = bytearray()
    while number > 127:
        result.append((number & 127) | 128)
        number >>= 7
    result.append(number)
    return bytes(result)


def wire(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode("utf-8")
    return varint((number << 3) | 2) + varint(len(value)) + value


def read_varint(data, pos):
    result = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise ValueError("Truncated protobuf varint")
        value = data[pos]
        pos += 1
        result |= (value & 127) << shift
        if value < 128:
            return result, pos
    raise ValueError("Oversized protobuf varint")


def protobuf_fields(data):
    pos = 0
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        number, kind = tag >> 3, tag & 7
        if not number:
            raise ValueError("Invalid protobuf field number")
        if kind == 0:
            value, pos = read_varint(data, pos)
        elif kind in (1, 2, 5):
            if kind == 2:
                size, pos = read_varint(data, pos)
            else:
                size = 8 if kind == 1 else 4
            if pos + size > len(data):
                raise ValueError("Truncated protobuf field")
            value, pos = data[pos:pos + size], pos + size
        else:
            raise ValueError(f"Unsupported protobuf wire type: {kind}")
        yield number, kind, value


def parse_dat(data, family, tags=None, ru_tags=False):
    record, found = empty(), []
    for number, kind, entry in protobuf_fields(data):
        if number != 1 or kind != 2:
            continue
        tag = next((v.decode("utf-8").upper() for n, k, v in protobuf_fields(entry) if n == 1 and k == 2), "")
        if tags is not None and tag not in {t.upper() for t in tags}:
            continue
        if ru_tags and tag != "RU" and not tag.endswith("-RU"):
            continue
        if not tag:
            continue
        fields = list(protobuf_fields(entry))
        # inverse_match in GeoIP means the complement, not an ordinary network list.
        if family == "geoip" and any(n == 3 and k == 0 and v for n, k, v in fields):
            raise ValueError("Inverted GeoIP entry is unsupported")
        found.append(tag)
        for n, k, message in fields:
            if n != 2 or k != 2:
                continue
            sub = list(protobuf_fields(message))
            if family == "geosite":
                typ = next((v for n, k, v in sub if n == 1 and k == 0), 0)
                value = next((v.decode("utf-8") for n, k, v in sub if n == 2 and k == 2), "")
                if typ not in DOMAIN_TYPES:
                    raise ValueError(f"Unknown GeoSite type {typ}")
                add(record, DOMAIN_TYPES[typ], value)
            else:
                packed = next((v for n, k, v in sub if n == 1 and k == 2), None)
                prefix = next((v for n, k, v in sub if n == 2 and k == 0), 0)
                if packed is None:
                    raise ValueError("GeoIP network without address")
                net = ipaddress.ip_network((ipaddress.ip_address(packed), prefix), strict=False)
                add(record, "ip_cidr", str(net))
    if not count(record):
        raise ValueError(f"No usable {family} entries in selected tags")
    return record, sorted(found)


def encode_geosite(groups):
    output = bytearray()
    types = {value: key for key, value in DOMAIN_TYPES.items()}
    for name, record in sorted(groups.items()):
        if not any(record.get(key) for key in DOMAIN_FIELDS):
            continue
        entry = bytearray(wire(1, name.upper()))
        for key in DOMAIN_FIELDS:
            for value in sorted(record.get(key, ())):
                entry.extend(wire(2, wire(1, types[key]) + wire(2, value)))
        output.extend(wire(1, bytes(entry)))
    return bytes(output)


def encode_geoip(groups):
    output = bytearray()
    for name, record in sorted(groups.items()):
        if not record.get("ip_cidr"):
            continue
        entry = bytearray(wire(1, name.upper()))
        for value in sorted(record["ip_cidr"]):
            net = ipaddress.ip_network(value)
            entry.extend(wire(2, wire(1, net.network_address.packed) + wire(2, net.prefixlen)))
        output.extend(wire(1, bytes(entry)))
    return bytes(output)


def source_json(record):
    # Separate rules explicitly express OR between domain and address families.
    domains = {key: sorted(record[key]) for key in DOMAIN_FIELDS if record.get(key)}
    rules = [domains] if domains else []
    if record.get("ip_cidr"):
        rules.append({"ip_cidr": sorted(record["ip_cidr"])})
    return {"version": 1, "rules": rules}


def domain_lines(record):
    lines = set(record.get("domain_suffix", ()))
    lines.update("full:" + value for value in record.get("domain", ()))
    lines.update("regexp:" + value for value in record.get("domain_regex", ()))
    lines.update("regexp:" + re.escape(value) for value in record.get("domain_keyword", ()))
    return sorted(lines)


def matches_domain(record, domain):
    domain = normalized_domain(domain)
    return (domain in record.get("domain", ())
            or any(".".join(domain.split(".")[i:]) in record.get("domain_suffix", ())
                   for i in range(len(domain.split("."))))
            or any(value in domain for value in record.get("domain_keyword", ()))
            or any(re.search(value, domain) for value in record.get("domain_regex", ())))


def collapse(record):
    result = merge(record)
    nets = [ipaddress.ip_network(value) for value in result["ip_cidr"]]
    result["ip_cidr"] = {str(net) for family in (4, 6)
                         for net in ipaddress.collapse_addresses(n for n in nets if n.version == family)}
    return result


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
