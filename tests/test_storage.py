import gzip
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from build import load_source
from storage import (BOT, SCHEMA_MARKER, clean_main, command, git, publish_cache,
                     retention_candidates, restore_cache, unpack_cache, validate_payload)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'project'
        self.root.mkdir()
        self.origin = self.base / 'remote.git'
        command(self.base, 'git', 'init', '--bare', str(self.origin))
        git(self.root, 'init', '-b', 'main')
        git(self.root, 'remote', 'add', 'origin', str(self.origin))
        (self.root / 'config').mkdir()
        self.source = {'id': 'example', 'url': 'https://example.com/list', 'format': 'text'}
        (self.root / 'config/sources.json').write_text(json.dumps({'sources': [self.source]}))
        self.cache = self.root / 'source-cache'
        self.cache.mkdir()
        load_source(self.source, self.cache, now=datetime(2026, 10, 23, tzinfo=timezone.utc),
                    downloader=lambda _: b'one.example\ntwo.example')
        (self.root / 'README.md').write_text('code')
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-m', 'Legacy project with generated data', env=BOT)
        git(self.root, 'push', 'origin', 'main')
        self.output = self.root / '.cache/output'
        (self.output / 'reports').mkdir(parents=True)
        (self.output / 'reports/manifest.json').write_text('{"sets":{}}')
        self.policy = {'keep_releases': 3, 'max_git_file_bytes': 45*1024**2,
                       'max_cache_bytes': 256*1024**2}

    def tearDown(self):
        self.temp.cleanup()

    def test_two_cache_publications_keep_one_commit_and_restore_fallback(self):
        code = git(self.root, 'rev-parse', 'HEAD')
        first = publish_cache(self.root, self.output, code, self.policy)
        snapshot = json.loads((self.cache / 'example.json').read_text())
        snapshot['rules']['domain_suffix'].append('three.example')
        (self.cache / 'example.json').write_text(json.dumps(snapshot))
        second = publish_cache(self.root, self.output, code, self.policy)
        self.assertNotEqual(first, second)
        self.assertEqual(git(self.origin, 'rev-list', '--count', 'data'), '1')
        self.assertEqual(git(self.origin, 'tag'), '')
        self.assertEqual(git(self.origin, 'rev-parse', 'main'), code)
        (self.cache / 'example.json').unlink()
        restore_cache(self.root)
        def fail(_):
            raise OSError('upstream unavailable')
        record, status = load_source(self.source, self.cache,
                                     now=datetime(2026, 10, 24, tzinfo=timezone.utc), downloader=fail)
        self.assertEqual(status['status'], 'cached')
        self.assertIn('three.example', record['domain_suffix'])
        self.assertEqual(status['last_success_at'], snapshot['last_success_at'])

    def test_main_migration_discards_generated_history_once(self):
        git(self.root, 'commit', '--allow-empty', '-m', 'Another legacy revision', env=BOT)
        git(self.root, 'push', 'origin', 'main')
        code = clean_main(self.root)
        self.assertEqual(git(self.origin, 'rev-list', '--count', 'main'), '1')
        self.assertEqual(git(self.origin, 'ls-tree', '--name-only', 'main'), 'README.md\nconfig')
        self.assertEqual(clean_main(self.root), code)
        git(self.root, 'reset', '--hard', code)
        self.assertEqual(clean_main(self.root), code)

    def test_code_migration_rejects_concurrent_main_change(self):
        expected = git(self.root, 'rev-parse', 'HEAD')
        git(self.root, 'commit', '--allow-empty', '-m', 'Concurrent owner edit', env=BOT)
        git(self.root, 'push', 'origin', 'main')
        git(self.root, 'reset', '--hard', expected)
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            clean_main(self.root)
        self.assertEqual(git(self.origin, 'rev-list', '--count', 'main'), '2')

    def test_corrupt_cache_cannot_overwrite_working_snapshot(self):
        original = (self.cache / 'example.json').read_bytes()
        with self.assertRaises((ValueError, OSError, EOFError)):
            unpack_cache(self.root, ['source-cache/example.json.gz'], lambda _: b'not gzip')
        self.assertEqual((self.cache / 'example.json').read_bytes(), original)
        with self.assertRaises(ValueError):
            unpack_cache(self.root, ['../example.json.gz'], lambda _: gzip.compress(original))

    def test_payload_tampering_stops_publication(self):
        dist = self.output / 'dist'
        dist.mkdir()
        (dist / 'example.lst').write_bytes(b'example.com\n')
        digest = hashlib.sha256((dist / 'example.lst').read_bytes()).hexdigest()
        (dist / 'sha256sums.txt').write_text(digest + '  example.lst\n')
        self.assertEqual(len(validate_payload(self.output)[0]), 2)
        (dist / 'example.lst').write_bytes(b'tampered.com\n')
        with self.assertRaises(ValueError):
            validate_payload(self.output)


class RetentionTests(unittest.TestCase):
    def release(self, day, *, draft=False, legacy=False, tag=None):
        return {'tag_name': tag or f'202610{day:02}-120000-123-1', 'draft': draft,
                'prerelease': False, 'body': '' if legacy else SCHEMA_MARKER,
                'published_at': f'2026-10-{day:02}T12:00:00Z',
                'created_at': f'2026-10-{day:02}T12:00:00Z'}

    def test_retains_three_successes_and_protects_latest_and_manual_releases(self):
        releases = [self.release(d) for d in range(19, 24)]
        releases += [self.release(18, legacy=True), self.release(20, draft=True),
                     self.release(23, draft=True, tag='20261023-130000-456-1'),
                     self.release(17, tag='manual-backup')]
        result = retention_candidates(releases, releases[4]['tag_name'], 3,
                                      datetime(2026, 10, 23, 18, tzinfo=timezone.utc))
        self.assertEqual({r['tag_name'] for r in result}, {
            self.release(19)['tag_name'], self.release(20)['tag_name'], self.release(18)['tag_name']})

    def test_legacy_publication_is_kept_until_new_schema_succeeds(self):
        old = self.release(22, legacy=True)
        self.assertEqual(retention_candidates([old], old['tag_name'], 3), [])
        new = self.release(23)
        draft = self.release(23, draft=True, legacy=True, tag='20261023-110000-999')
        self.assertEqual(retention_candidates([old, new, draft], new['tag_name'], 3), [old, draft])


if __name__ == '__main__':
    unittest.main()
