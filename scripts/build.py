#!/usr/bin/env python3
"""Fetch independent sources, validate snapshots and publish consistent exports."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import gzip
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

from routing import (DOMAIN_FIELDS, FIELDS, collapse, count, domain_lines, empty,
                     encode_geoip, encode_geosite, matches_domain, merge, parse_dat,
                     parse_json, parse_text, serial, source_json, write_json)

ROOT = Path(__file__).resolve().parent.parent
MAX_DOWNLOAD = 100 * 1024 * 1024


def utcnow():
    return datetime.now(timezone.utc)


def fetch(url):
    if not url.startswith("https://"):
        raise ValueError("Source URLs must use HTTPS")
    error = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "cheburnator-routing/1.0"})
            with urllib.request.urlopen(request, timeout=40) as response:
                if not response.url.startswith("https://"):
                    raise ValueError("Insecure redirect")
                data = response.read(MAX_DOWNLOAD + 1)
            if not data or len(data) > MAX_DOWNLOAD:
                raise ValueError("Empty or oversized source")
            return data
        except (OSError, ValueError) as exc:
            error = exc
            if attempt < 2:
                time.sleep(attempt + 1)
    raise RuntimeError(str(error))


def parse_source(source, data):
    fmt = source["format"]
    if fmt in ("geosite", "geoip"):
        record, tags = parse_dat(data, fmt, tags=source.get("tags"), ru_tags=source.get("ru_tags", False))
        return record, {"selected_tags": tags}
    if fmt == "json":
        return parse_json(data.decode("utf-8-sig")), {}
    details = {}
    record = parse_text(data.decode("utf-8-sig"), source.get("family", "domains"),
                        max_invalid=source.get("max_invalid_lines", 0), quarantine=details)
    return record, details


def load_source(source, cache_dir, offline=False, now=None, downloader=fetch):
    now = now or utcnow()
    path = cache_dir / (source["id"] + ".json")
    previous = json.loads(path.read_text()) if path.exists() else None
    error = None
    if not offline:
        try:
            data = downloader(source["url"])
            record, details = parse_source(source, data)
            size = count(record)
            if size < source.get("min_entries", 1):
                raise ValueError(f"Too few entries: {size}")
            if (previous and size < count(previous["rules"]) * source.get("min_retained_ratio", 0.5)):
                raise ValueError(f"Unexpected shrink: {count(previous['rules'])} -> {size}")
            digest = hashlib.sha256(data).hexdigest()
            unchanged = previous and previous["sha256"] == digest
            snapshot = {"url": source["url"], "sha256": digest, "last_success_at": now.isoformat(),
                        "content_changed_at": previous["content_changed_at"] if unchanged else now.isoformat(),
                        "rules": serial(record), **details}
            write_json(path, snapshot)
            return record, {"id": source["id"], "status": "unchanged" if unchanged else "updated",
                            "entries": size, **{k: v for k, v in snapshot.items() if k != "rules"}}
        except (ValueError, RuntimeError, OSError, UnicodeError) as exc:
            error = str(exc)
    if previous and previous.get("url") == source["url"]:
        age = now - datetime.fromisoformat(previous["last_success_at"])
        if age <= timedelta(days=source.get("max_cache_days", 14)):
            record = merge(previous["rules"])
            return record, {"id": source["id"], "status": "cached", "error": error or "offline build",
                            "entries": count(record),
                            **{k: v for k, v in previous.items() if k != "rules"}}
        error = (error or "offline build") + f"; cache expired ({age.days} days)"
    return None, {"id": source["id"], "url": source["url"], "status": "unavailable",
                  "error": error or "no cached snapshot", "entries": 0}


def load_override(path):
    return parse_text(path.read_text(encoding="utf-8"), allow_empty=True)


def check_overrides(direct, proxy):
    # Broad parent exceptions with opposite children require an explicit redesign,
    # rather than relying on an undocumented order between two force lists.
    for left, right in ((direct, proxy), (proxy, direct)):
        for key in ("domain", "domain_suffix"):
            for domain in left[key]:
                if matches_domain(right, domain):
                    raise ValueError(f"Conflicting force-direct/force-proxy overrides: {domain}")
    if (direct["domain_regex"] or direct["domain_keyword"] or proxy["domain_regex"] or proxy["domain_keyword"]):
        raise ValueError("Force overrides support exact/suffix domains only; regex conflicts cannot be proved safe")


def exclude_rules(record, exclusions):
    result = merge(record)
    for key in DOMAIN_FIELDS:
        result[key].difference_update(exclusions[key])
    # A suffix exclusion removes imported subdomains, but does not delete broader
    # parent rules (which would silently remove unrelated sites).
    suffix_exclusions = {"domain_suffix": exclusions["domain_suffix"]}
    for key in ("domain", "domain_suffix"):
        result[key] = {d for d in result[key] if not matches_domain(suffix_exclusions, d)}
    return result


def export_group(base, name, record, report):
    lists, rulesets, artifacts = base / "lists", base / "rule-set", base / "dist"
    for directory in (lists, rulesets, artifacts):
        directory.mkdir(parents=True, exist_ok=True)
    obj = source_json(record)
    write_json(rulesets / f"{name}.json", obj)
    write_json(artifacts / f"{name}.json", obj)
    if any(record[key] for key in DOMAIN_FIELDS):
        (lists / f"{name}.lst").write_text("\n".join(domain_lines(record)) + "\n")
        # Pure suffix export is intentionally separate from the panel's typed LST.
        (lists / f"{name}-suffix.lst").write_text("\n".join(sorted(record["domain_suffix"])) + "\n")
        nft_lines = [f"nftset=/{d}/4#inet#fw4#vpn_domains4,6#inet#fw4#vpn_domains6"
                     for d in sorted(record["domain_suffix"])]
        ipset_lines = [f"ipset=/{d}/vpn_domains4,vpn_domains6" for d in sorted(record["domain_suffix"])]
        (artifacts / f"{name}-dnsmasq-nftset.conf").write_text("\n".join(nft_lines) + "\n")
        (artifacts / f"{name}-dnsmasq-ipset.conf").write_text("\n".join(ipset_lines) + "\n")
        report["dnsmasq_omitted"] = {k: len(record[k]) for k in ("domain", "domain_keyword", "domain_regex") if record[k]}
    if record["ip_cidr"]:
        (lists / f"{name}.lst").write_text("\n".join(sorted(record["ip_cidr"])) + "\n")
        for version in (4, 6):
            values = [v for v in sorted(record["ip_cidr"]) if (":" in v) == (version == 6)]
            (lists / f"{name}-v{version}.lst").write_text(
                "\n".join(values) + "\n" if values else f"# No IPv{version} routes in this set.\n")
    report["fields"] = {k: len(v) for k, v in record.items() if v}


def compile_exports(base, groups, reports, sing_box=None, mihomo=None):
    artifacts = base / "dist"
    for name, record in groups.items():
        if sing_box:
            source = artifacts / f"{name}.json"
            target = artifacts / f"{name}.srs"
            subprocess.run([sing_box, "rule-set", "compile", str(source), "-o", str(target)], check=True, capture_output=True)
            decoded = artifacts / f"{name}.decoded.json"
            subprocess.run([sing_box, "rule-set", "decompile", str(target), "-o", str(decoded)], check=True, capture_output=True)
            # Binary version may change, but the reconstructed matching fields must not.
            before = parse_json(source.read_text())
            after = parse_json(decoded.read_text())
            if serial(before) != serial(after):
                raise ValueError(f"SRS round-trip changed rules in {name}")
            decoded.unlink()
        if mihomo:
            domain_values = sorted(set(record["domain"]) | {"+." + v for v in record["domain_suffix"]})
            for behavior, values in (("domain", domain_values), ("ipcidr", sorted(record["ip_cidr"]))):
                if not values:
                    continue
                source = artifacts / f"{name}-{behavior}.text"
                source.write_text("\n".join(values) + "\n")
                target = artifacts / f"{name}-{behavior}.mrs"
                subprocess.run([mihomo, "convert-ruleset", behavior, "text", str(source),
                                str(target)], check=True, capture_output=True)
                decoded = artifacts / f"{name}-{behavior}.decoded"
                subprocess.run([mihomo, "convert-ruleset", behavior, "mrs", str(target),
                                str(decoded)], check=True, capture_output=True)
                verify_mrs(record, behavior, decoded.read_text().splitlines())
                decoded.unlink()
                source.unlink()
            reports[name]["mrs_omitted"] = {k: len(record[k]) for k in ("domain_keyword", "domain_regex") if record[k]}


def verify_mrs(record, behavior, lines):
    if behavior == "ipcidr":
        expected = collapse(record)["ip_cidr"]
        actual = collapse({"ip_cidr": {str(ipaddress.ip_network(v, strict=False)) for v in lines}})["ip_cidr"]
        if actual != expected:
            raise ValueError("MRS round-trip changed IP coverage")
        return
    suffixes = {line[2:] for line in lines if line.startswith("+.")}
    exact = {line for line in lines if not line.startswith("+.")}
    def covered(suffix_set, domain):
        parts = domain.split(".")
        return any(".".join(parts[i:]) in suffix_set for i in range(len(parts)))
    # Mihomo removes redundant descendants, so compare coverage, not line counts.
    if any(not covered(suffixes, value) for value in record["domain_suffix"]):
        raise ValueError("MRS lost a suffix rule")
    if any(value not in exact and not covered(suffixes, value) for value in record["domain"]):
        raise ValueError("MRS lost an exact domain")
    if any(not covered(record["domain_suffix"], value) for value in suffixes):
        raise ValueError("MRS broadened a suffix rule")
    if any(value not in record["domain"] and not covered(record["domain_suffix"], value) for value in exact):
        raise ValueError("MRS added an exact domain")


def build(root, output, offline=False, sing_box=None, mihomo=None, xray=None):
    if output == root or output in root.parents:
        raise ValueError("Output must not replace the project or its parent directory")
    config = json.loads((root / "config/sources.json").read_text())
    sources = config["sources"]
    ids = [s["id"] for s in sources]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate source IDs")
    cache = root / "source-cache"
    cache.mkdir(exist_ok=True)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda s: load_source(s, cache, offline), sources))
    statuses = [status for _, status in results]
    available = {source["id"]: record for source, (record, _) in zip(sources, results)}
    failures = [s["id"] for s, (record, _) in zip(sources, results) if record is None and s.get("required", False)]
    groups, origins = {}, {}
    for source, (record, status) in zip(sources, results):
        print(f"{source['id']}: {status['status']} ({status['entries']})", flush=True)
        if record is None:
            continue
        if source.get("fallback_for") and available.get(source["fallback_for"]) is not None:
            status["used"] = False
            status["note"] = "standby snapshot; primary source available"
            continue
        status["used"] = True
        for group in source["groups"]:
            projected = merge(record)
            if group.endswith("-domains") or group.startswith("category-"):
                projected["ip_cidr"].clear()
            elif group.endswith("-ips"):
                for key in DOMAIN_FIELDS:
                    projected[key].clear()
            if not count(projected):
                continue
            groups[group] = merge(groups.get(group, empty()), projected)
            origins.setdefault(group, []).append(source["id"])
    for group, minimum in config.get("minimum_sources", {}).items():
        if len(origins.get(group, [])) < minimum:
            failures.append(f"{group}: requires {minimum} source snapshots")
    providers = {s["id"]: s.get("provider", s["id"]) for s in sources}
    for group, minimum in config.get("minimum_providers", {}).items():
        if len({providers[id] for id in origins.get(group, [])}) < minimum:
            failures.append(f"{group}: requires {minimum} upstream providers")
    if failures:
        raise ValueError("Cannot publish incomplete build: " + ", ".join(failures))

    direct = load_override(root / "overrides/force-direct.lst")
    proxy = load_override(root / "overrides/force-proxy.lst")
    check_overrides(direct, proxy)
    exclusions = load_override(root / "overrides/exclude-proxy.lst")
    groups["proxy-domains"] = exclude_rules(groups["proxy-domains"], exclusions)
    groups["force-direct"] = direct
    groups["force-proxy"] = proxy
    groups = {name: collapse(record) for name, record in groups.items() if count(record)}
    reports = {name: {"sources": origins.get(name, ["local overrides"])} for name in groups}

    overlaps = []
    ru = groups["ru-domains"]
    for key in ("domain", "domain_suffix"):
        for domain in sorted(groups["proxy-domains"][key]):
            if matches_domain(ru, domain):
                overlaps.append({"domain": domain, "type": key, "resolution": "proxy domain before general RU rules"})

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".build-", dir=output.parent) as temp:
        stage = Path(temp)
        for name, record in groups.items():
            export_group(stage, name, record, reports[name])
        artifacts = stage / "dist"
        (artifacts / "geosite.dat").write_bytes(encode_geosite(groups))
        (artifacts / "geosite-compact.dat").write_bytes(encode_geosite({k: v for k, v in groups.items() if k != "proxy-domains"}))
        (artifacts / "geoip.dat").write_bytes(encode_geoip(groups))
        # Independent decode check on the emitted protobuf files.
        gs_data, gi_data = (artifacts / "geosite.dat").read_bytes(), (artifacts / "geoip.dat").read_bytes()
        for name, record in groups.items():
            if any(record[k] for k in DOMAIN_FIELDS):
                decoded, _ = parse_dat(gs_data, "geosite", tags=[name])
                if serial(decoded) != serial({k: record[k] for k in DOMAIN_FIELDS}):
                    raise ValueError(f"GeoSite round-trip failed: {name}")
            if record["ip_cidr"]:
                decoded, _ = parse_dat(gi_data, "geoip", tags=[name])
                if decoded["ip_cidr"] != record["ip_cidr"]:
                    raise ValueError(f"GeoIP round-trip failed: {name}")
        compile_exports(stage, groups, reports, sing_box, mihomo)
        if xray:
            rules = []
            for name, record in groups.items():
                if any(record[k] for k in DOMAIN_FIELDS):
                    rules.append({"type": "field", "domain": [f"ext:geosite.dat:{name}"], "outboundTag": "test"})
                    if name != "proxy-domains":
                        rules.append({"type": "field", "domain": [f"ext:geosite-compact.dat:{name}"], "outboundTag": "test"})
                if record["ip_cidr"]:
                    rules.append({"type": "field", "ip": [f"ext:geoip.dat:{name}"], "outboundTag": "test"})
            config = stage / "xray-validation.json"
            write_json(config, {"outbounds": [{"protocol": "blackhole", "tag": "test"}], "routing": {"rules": rules}})
            env = {**os.environ, "XRAY_LOCATION_ASSET": str(artifacts)}
            subprocess.run([xray, "run", "-test", "-config", str(config)], check=True, capture_output=True, env=env)
            config.unlink()
        write_json(stage / "reports/conflicts.json", overlaps)
        write_json(stage / "reports/manifest.json", {"built_at": utcnow().isoformat(), "sources": statuses,
                   "sets": reports, "overlap_count": len(overlaps),
                   "formats": {"srs": bool(sing_box), "mrs": bool(mihomo), "dat": True},
                   "xray_native_validation": bool(xray)})
        # Copy list downloads into the release payload with globally unique names.
        for file in (stage / "lists").glob("*.lst"):
            shutil.copy2(file, artifacts / file.name)
        shutil.copy2(stage / "reports/manifest.json", artifacts / "manifest.json")
        (artifacts / "conflicts.json.gz").write_bytes(gzip.compress(
            (stage / "reports/conflicts.json").read_bytes(), compresslevel=9, mtime=0))
        (artifacts / "sha256sums.txt").write_text("".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in sorted(artifacts.iterdir()) if p.is_file()))
        previous_output = Path(tempfile.mkdtemp(prefix=".build-previous-", dir=output.parent))
        previous_output.rmdir()
        if output.exists():
            os.replace(output, previous_output)
        try:
            os.replace(stage, output)
        except OSError:
            if previous_output.exists():
                os.replace(previous_output, output)
            raise
        finally:
            if previous_output.exists():
                shutil.rmtree(previous_output)
    return groups, statuses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=ROOT / ".cache/output")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--sing-box", help="Path to the sing-box executable")
    parser.add_argument("--mihomo", help="Path to the mihomo executable")
    parser.add_argument("--xray", help="Validate every DAT tag with an Xray executable")
    args = parser.parse_args()
    try:
        groups, statuses = build(args.root.resolve(), args.output.resolve(), args.offline, args.sing_box, args.mihomo, args.xray)
        print(f"Built {len(groups)} sets; cached/unavailable sources: "
              f"{sum(s['status'] in ('cached', 'unavailable') for s in statuses)}")
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"")
        print(f"Build failed: {exc}\n{detail.decode(errors='replace') if isinstance(detail, bytes) else detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
