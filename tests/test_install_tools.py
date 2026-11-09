import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from install_tools import fetch_verified

PAYLOAD = b'compiler archive bytes'
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class FakeOpener:
    """Plays back a script of results: bytes are returned, exceptions are raised."""

    def __init__(self, *script):
        self.script = list(script)
        self.calls = 0

    def __call__(self, url, timeout):
        self.calls += 1
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        return io.BytesIO(step)


class FetchVerifiedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cache = Path(self.temp.name) / 'downloads'
        self.sleeps = []
        self.warnings = []

    def tearDown(self):
        self.temp.cleanup()

    def fetch(self, opener, attempts=4):
        return fetch_verified('tool', 'https://example.invalid/tool', DIGEST, self.cache, opener=opener,
                              sleep=self.sleeps.append, attempts=attempts, warn=self.warnings.append)

    def test_read_timeout_is_retried_then_succeeds(self):
        opener = FakeOpener(TimeoutError('The read operation timed out'), PAYLOAD)
        self.assertEqual(self.fetch(opener), PAYLOAD)
        self.assertEqual(opener.calls, 2)
        self.assertEqual(self.sleeps, [10])
        self.assertIn('timed out', self.warnings[0])

    def test_connection_errors_and_5xx_are_retried(self):
        opener = FakeOpener(urllib.error.URLError('reset'),
                            urllib.error.HTTPError('u', 502, 'Bad Gateway', {}, None), PAYLOAD)
        self.assertEqual(self.fetch(opener), PAYLOAD)
        self.assertEqual(self.sleeps, [10, 30])

    def test_corrupted_download_is_retried_and_never_returned(self):
        opener = FakeOpener(b'truncated', PAYLOAD)
        self.assertEqual(self.fetch(opener), PAYLOAD)
        self.assertIn('Checksum mismatch', self.warnings[0])

    def test_gives_up_after_all_attempts(self):
        opener = FakeOpener(*[TimeoutError('slow')] * 3)
        with self.assertRaisesRegex(RuntimeError, 'after 3 attempts'):
            self.fetch(opener, attempts=3)
        self.assertEqual(opener.calls, 3)
        self.assertEqual(self.sleeps, [10, 30])

    def test_client_error_fails_fast(self):
        opener = FakeOpener(urllib.error.HTTPError('u', 404, 'Not Found', {}, None))
        with self.assertRaises(urllib.error.HTTPError):
            self.fetch(opener)
        self.assertEqual(opener.calls, 1)
        self.assertEqual(self.sleeps, [])

    def test_verified_cache_skips_network(self):
        self.assertEqual(self.fetch(FakeOpener(PAYLOAD)), PAYLOAD)
        offline = FakeOpener()
        self.assertEqual(self.fetch(offline), PAYLOAD)
        self.assertEqual(offline.calls, 0)

    def test_tampered_cache_is_discarded(self):
        self.cache.mkdir(parents=True)
        (self.cache / DIGEST).write_bytes(b'tampered')
        opener = FakeOpener(PAYLOAD)
        self.assertEqual(self.fetch(opener), PAYLOAD)
        self.assertEqual(opener.calls, 1)
        self.assertEqual((self.cache / DIGEST).read_bytes(), PAYLOAD)


if __name__ == '__main__':
    unittest.main()
