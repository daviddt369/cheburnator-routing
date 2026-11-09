#!/usr/bin/env python3
"""Install pinned Linux amd64 rule compilers, checking release SHA-256 digests.

Downloads are retried with backoff, and verified archives are kept in
tools/.downloads/<sha256> so a CI cache can skip the network entirely. Every
archive, cached or fresh, is checked against its pinned digest before use.
"""
import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent / "tools"
TOOLS = [
    ("sing-box", "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz",
     "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee"),
    ("mihomo", "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1.19.33.gz",
     "132f6f3edf9a65e62f04853aed3358472e0b2b7666daa8419edfa2ddf5bb6323"),
    ("xray", "https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip",
     "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978"),
]
ATTEMPTS = 4
TIMEOUT = 60
BACKOFF = (10, 30, 60)


def _warn(message):
    print(message, file=sys.stderr, flush=True)


def fetch_verified(name, url, digest, cache_dir, opener=urllib.request.urlopen, sleep=time.sleep,
                   attempts=ATTEMPTS, timeout=TIMEOUT, warn=_warn):
    """Return archive bytes whose SHA-256 equals digest, from the cache or the network."""
    cached = cache_dir / digest
    if cached.is_file():
        data = cached.read_bytes()
        if hashlib.sha256(data).hexdigest() == digest:
            print(f"Using cached {name} archive")
            return data
        cached.unlink()
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            with opener(url, timeout=timeout) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError(f"Checksum mismatch for {name}")
            cache_dir.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(data)
            return data
        except urllib.error.HTTPError as error:
            if 400 <= error.code < 500 and error.code != 429:
                raise
            last_error = error
        except (ValueError, OSError) as error:  # URLError, TimeoutError and ConnectionError are OSError
            last_error = error
        if attempt < attempts:
            delay = BACKOFF[min(attempt - 1, len(BACKOFF) - 1)]
            warn(f"Download of {name} failed (attempt {attempt}/{attempts}: {last_error!r}); retrying in {delay}s")
            sleep(delay)
    raise RuntimeError(f"Could not download a verified {name} after {attempts} attempts: {last_error!r}")


def main():
    ROOT.mkdir(exist_ok=True)
    cache_dir = ROOT / ".downloads"
    for name, url, digest in TOOLS:
        data = fetch_verified(name, url, digest, cache_dir)
        if name == "sing-box":
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                for filename in ("sing-box", "libcronet.so"):
                    members = [m for m in archive.getmembers() if m.isfile() and m.name.endswith("/" + filename)]
                    if filename == "sing-box" and len(members) != 1:
                        raise ValueError("Unexpected sing-box archive structure")
                    if members:
                        (ROOT / filename).write_bytes(archive.extractfile(members[0]).read())
        elif name == "xray":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                (ROOT / name).write_bytes(archive.read("xray"))
        else:
            (ROOT / name).write_bytes(gzip.decompress(data))
        (ROOT / name).chmod(0o755)
        print(f"Verified and installed {name}")


if __name__ == "__main__":
    main()
