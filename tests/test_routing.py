import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from routing import (collapse, domain_lines, encode_geosite, encode_geoip, matches_domain,
                     parse_dat, parse_json, parse_text, serial, source_json, wire)
from build import build, check_overrides, exclude_rules, load_source, verify_mrs, utcnow, export_group


class RoutingTests(unittest.TestCase):
    def test_mixed_upstream_keeps_ips_in_separate_field(self):
        record = parse_text('"example.com\n8.8.8.8\n2001:4860::/32', 'mixed')
        self.assertEqual(record['domain_suffix'], {'example.com'})
        self.assertEqual(record['ip_cidr'], {'8.8.8.8/32', '2001:4860::/32'})

    def test_quarantine_is_explicit_and_bounded(self):
        details = {}
        text = '\n'.join(f'host{i}.example' for i in range(2000)) + '\n<html>bad</html>'
        record = parse_text(text, max_invalid=1, quarantine=details)
        self.assertEqual(details['invalid_count'], 1)
        self.assertEqual(len(record['domain_suffix']), 2000)
        with self.assertRaises(ValueError):
            parse_text('<html>bad</html>', max_invalid=100)

    def test_mixed_single_labels_are_quarantined_without_losing_ips(self):
        details = {}
        valid = '\n'.join(f'host{i}.example' for i in range(4000))
        text = valid + '\nn\nfull:casino167\ndomain:moscowdiplom\n8.8.8.8\n2001:4860::/32'
        record = parse_text(text, 'mixed', max_invalid=3, quarantine=details)
        self.assertEqual(details['invalid_count'], 3)
        self.assertEqual(len(record['domain_suffix']), 4000)
        self.assertFalse(record['domain'])
        self.assertEqual(record['ip_cidr'], {'8.8.8.8/32', '2001:4860::/32'})
        with self.assertRaises(ValueError):
            parse_text(text, 'mixed', max_invalid=2)

    def test_domain_sources_keep_intentional_tld_rules(self):
        record = parse_text('ua\nru\nпример.рф')
        self.assertTrue(matches_domain(record, 'example.ua'))
        self.assertTrue(matches_domain(record, 'example.ru'))
        decoded, _ = parse_dat(encode_geosite({'test': record}), 'geosite', tags=['test'])
        self.assertEqual(serial(decoded), serial(record))

    def test_mrs_minimization_keeps_semantics(self):
        record = parse_text('example.com\nsub.example.com\nfull:other.example')
        verify_mrs(record, 'domain', ['+.example.com', 'other.example'])
        with self.assertRaises(ValueError):
            verify_mrs(parse_text('full:other.example'), 'domain', ['+.other.example'])
    def test_domain_types_and_idn_are_preserved(self):
        rules = parse_text("пример.рф\nfull:API.Example.COM\nregexp:^MiXeD[0-9]\\.example$\nkeyword:MiXeD\n")
        self.assertIn("xn--e1afmkfd.xn--p1ai", rules["domain_suffix"])
        self.assertEqual(rules["domain"], {"api.example.com"})
        self.assertIn("^MiXeD[0-9]\\.example$", rules["domain_regex"])
        self.assertIn("MiXeD", rules["domain_keyword"])
        decoded, tags = parse_dat(encode_geosite({"example": rules}), "geosite", tags=["example"])
        self.assertEqual(serial(decoded), serial(rules))
        self.assertEqual(tags, ["EXAMPLE"])

    def test_suffix_matches_dns_boundary_only(self):
        rules = parse_text("example.com")
        self.assertTrue(matches_domain(rules, "a.example.com"))
        self.assertFalse(matches_domain(rules, "notexample.com"))

    def test_typed_lst_does_not_broaden_exact_matches(self):
        rules = parse_text("example.net\nfull:api.example.com\nregexp:^x[0-9]+\\.example$")
        self.assertEqual(serial(parse_text("\n".join(domain_lines(rules)))), serial(rules))
        self.assertFalse(matches_domain(rules, "sub.api.example.com"))

    def test_geoip_protobuf_ipv4_ipv6_and_collapse(self):
        rules = collapse(parse_text("8.8.8.0/25\n8.8.8.128/25\n2001:4860::/32", "ips"))
        self.assertIn("8.8.8.0/24", rules["ip_cidr"])
        decoded, _ = parse_dat(encode_geoip({"RU": rules}), "geoip", tags=["RU"])
        self.assertEqual(serial(decoded), serial(rules))

    def test_bad_input_cannot_become_a_route(self):
        for text in ("<html>upstream error</html>", "https://example.com", "8.8.8.8", "bad domain"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_text(text)
        for text in ("10.0.0.0/8", "127.0.0.1", "::1"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_text(text, "ips")
        with self.assertRaises(ValueError):
            parse_dat(b"\x0a\xff", "geosite")
        with self.assertRaises(ValueError):
            parse_json('{"rules":[{"type":"logical","mode":"and","rules":[]}]}')

    def test_inverted_geoip_is_rejected(self):
        cidr = wire(1, bytes([8, 8, 8, 0])) + wire(2, 24)
        data = wire(1, wire(1, "RU") + wire(2, cidr) + wire(3, 1))
        with self.assertRaises(ValueError):
            parse_dat(data, "geoip", tags=["RU"])

    def test_force_overrides_reject_parent_child_conflict(self):
        with self.assertRaises(ValueError):
            check_overrides(parse_text("example.com"), parse_text("api.example.com"))
        with self.assertRaises(ValueError):
            check_overrides(parse_text("api.example.com"), parse_text("example.com"))
        check_overrides(parse_text("example.com"), parse_text("other.example"))

    def test_excluding_ru_does_not_erase_proxy_domains_implicitly(self):
        rules = parse_text("blocked.ru\nexample.com\napi.example.com")
        exclusions = parse_text("api.example.com")
        result = exclude_rules(rules, exclusions)
        self.assertIn("blocked.ru", result["domain_suffix"])
        self.assertIn("example.com", result["domain_suffix"])
        self.assertNotIn("api.example.com", result["domain_suffix"])

    def test_source_json_domains_and_ips_are_separate_or_rules(self):
        rules = parse_text("example.com")
        rules["ip_cidr"].add("8.8.8.0/24")
        obj = source_json(rules)
        self.assertEqual(len(obj["rules"]), 2)
        self.assertEqual(serial(parse_json(json.dumps(obj))), serial(rules))

    def test_empty_ip_family_is_uploadable_and_contains_no_routes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            export_group(root, 'example-ips', parse_text('8.8.8.0/24', 'ips'), {})
            file = root / 'lists/example-ips-v6.lst'
            self.assertGreater(file.stat().st_size, 0)
            self.assertEqual(parse_text(file.read_text(), 'ips', allow_empty=True)['ip_cidr'], set())


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cache = Path(self.temp.name)
        self.now = datetime(2026, 10, 23, tzinfo=timezone.utc)
        self.source = {"id": "test", "url": "https://example.com/list", "format": "text", "max_cache_days": 14}

    def tearDown(self):
        self.temp.cleanup()

    def initial(self):
        return load_source(self.source, self.cache, now=self.now,
                           downloader=lambda _: b"one.example\ntwo.example\nthree.example\nfour.example")

    def test_http_error_keeps_last_success_time(self):
        original, _ = self.initial()
        def fail(_):
            raise OSError("unavailable")
        record, status = load_source(self.source, self.cache, now=self.now + timedelta(days=2), downloader=fail)
        self.assertEqual(status["status"], "cached")
        self.assertEqual(serial(record), serial(original))
        self.assertEqual(status["last_success_at"], self.now.isoformat())

    def test_shrink_and_html_do_not_poison_snapshot(self):
        original, _ = self.initial()
        for payload in (b"one.example", b"<html>error</html>"):
            record, status = load_source(self.source, self.cache, now=self.now, downloader=lambda _: payload)
            self.assertEqual(status["status"], "cached")
            self.assertEqual(serial(record), serial(original))

    def test_expired_cache_is_not_reported_as_fresh(self):
        self.initial()
        record, status = load_source(self.source, self.cache, offline=True, now=self.now + timedelta(days=15))
        self.assertIsNone(record)
        self.assertEqual(status["status"], "unavailable")

    def test_url_change_cannot_reuse_unrelated_cache(self):
        self.initial()
        changed = {**self.source, "url": "https://example.org/new"}
        record, status = load_source(changed, self.cache, offline=True, now=self.now)
        self.assertIsNone(record)

    def test_incomplete_build_leaves_previous_output_untouched(self):
        root = self.cache / "project"
        (root / "config").mkdir(parents=True)
        (root / "config/sources.json").write_text(json.dumps({"sources":[
            {**self.source, "required": True, "groups": ["proxy-domains"]}]}))
        output = root / "output"
        output.mkdir()
        (output / "sentinel").write_text("working")
        with self.assertRaises(ValueError):
            build(root, output, offline=True)
        self.assertEqual((output / "sentinel").read_text(), "working")

    def test_standby_ru_data_is_used_only_when_primary_expires(self):
        root = self.cache / 'fallback-project'
        (root / 'config').mkdir(parents=True)
        (root / 'overrides').mkdir()
        for name in ('force-direct', 'force-proxy', 'exclude-proxy'):
            (root / 'overrides' / (name + '.lst')).write_text('# empty\n')
        sources = [
            {'id':'primary','url':'https://example.com/primary','format':'text','groups':['ru-domains']},
            {'id':'standby','url':'https://example.com/standby','format':'text','groups':['ru-domains'],'fallback_for':'primary'},
            {'id':'proxy','url':'https://example.com/proxy','format':'text','groups':['proxy-domains']},
        ]
        (root / 'config/sources.json').write_text(json.dumps({'sources': sources}))
        data = [b'real.ru', b'foreign-check.example', b'blocked.ru']
        for source, payload in zip(sources, data):
            load_source(source, root / 'source-cache', downloader=lambda _, p=payload: p)
        groups, statuses = build(root, root / 'out', offline=True)
        self.assertEqual(groups['ru-domains']['domain_suffix'], {'real.ru'})
        self.assertFalse(next(s for s in statuses if s['id']=='standby')['used'])
        path = root / 'source-cache/primary.json'
        snapshot = json.loads(path.read_text())
        snapshot['last_success_at'] = (utcnow() - timedelta(days=15)).isoformat()
        path.write_text(json.dumps(snapshot))
        groups, statuses = build(root, root / 'out', offline=True)
        self.assertEqual(groups['ru-domains']['domain_suffix'], {'foreign-check.example'})


if __name__ == "__main__":
    unittest.main()
