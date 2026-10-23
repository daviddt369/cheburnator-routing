#!/usr/bin/env python3
"""Publish bounded routing storage: code history, one cache snapshot, three releases."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
GENERATED = ('lists', 'rule-set', 'reports', 'source-cache')
MANAGED_TAG = re.compile(r'^\d{8}-\d{6}-\d+(?:-\d+)?$')
SCHEMA_MARKER = 'Storage schema: 2'
MAX_UNPACKED = 100 * 1024 * 1024
BOT = {'GIT_AUTHOR_NAME': 'github-actions[bot]',
       'GIT_AUTHOR_EMAIL': '41898282+github-actions[bot]@users.noreply.github.com',
       'GIT_COMMITTER_NAME': 'github-actions[bot]',
       'GIT_COMMITTER_EMAIL': '41898282+github-actions[bot]@users.noreply.github.com'}


def command(root, *args, env=None, binary=False):
    return subprocess.run(args, cwd=root, env={**os.environ, **(env or {})},
                          check=True, capture_output=True, text=not binary).stdout


def git(root, *args, **kwargs):
    return command(root, 'git', *args, **kwargs).strip()


def remote_sha(root, branch):
    result = subprocess.run(['git', 'ls-remote', '--exit-code', '--heads', 'origin',
                             f'refs/heads/{branch}'], cwd=root, capture_output=True, text=True)
    if result.returncode == 2:
        return ''
    result.check_returncode()
    return result.stdout.split()[0]


def root_commit(root, directory, message):
    with tempfile.TemporaryDirectory() as temp:
        env = {**BOT, 'GIT_INDEX_FILE': str(Path(temp) / 'index')}
        git(root, 'read-tree', '--empty', env=env)
        git(root, '--work-tree', str(directory), 'add', '--all', '--force', env=env)
        tree = git(root, 'write-tree', env=env)
        return git(root, 'commit-tree', tree, '-m', message, env=env)


def clean_main(root):
    """One-time migration of this project's generated history; future code history stays."""
    head = git(root, 'rev-parse', 'HEAD')
    tracked = git(root, 'ls-tree', '--name-only', head, *GENERATED)
    if not tracked:
        return head
    with tempfile.TemporaryDirectory() as temp:
        env = {**BOT, 'GIT_INDEX_FILE': str(Path(temp) / 'index')}
        git(root, 'read-tree', head, env=env)
        git(root, 'rm', '-r', '--cached', '--ignore-unmatch', *GENERATED, env=env)
        tree = git(root, 'write-tree', env=env)
        if remote_sha(root, 'main') != head:
            git(root, 'fetch', '--no-tags', '--depth=1', 'origin', 'refs/heads/main')
            if git(root, 'rev-parse', 'FETCH_HEAD^{tree}') == tree:
                # An already queued run may still have the pre-migration checkout.
                return git(root, 'rev-parse', 'FETCH_HEAD')
            raise ValueError('Newer main code exists; refusing to overwrite it during migration')
        code = git(root, 'commit-tree', tree, '-m', 'Start code-only routing history', env=env)
    git(root, 'push', f'--force-with-lease=refs/heads/main:{head}', 'origin',
        f'{code}:refs/heads/main')
    print(f'Migrated main to code-only root {code}', flush=True)
    return code


def stage_cache(root, output, destination, code_sha, policy):
    target = destination / 'source-cache'
    target.mkdir(parents=True)
    configured = {s['id'] for s in json.loads((root / 'config/sources.json').read_text())['sources']}
    for source in sorted((root / 'source-cache').glob('*.json')):
        if source.stem not in configured:
            continue
        (target / (source.name + '.gz')).write_bytes(gzip.compress(source.read_bytes(), compresslevel=9, mtime=0))
    if not list(target.iterdir()):
        raise ValueError('Refusing to publish an empty source cache')
    shutil.copy2(output / 'reports/manifest.json', destination / 'manifest.json')
    files = list(destination.rglob('*'))
    sizes = [p.stat().st_size for p in files if p.is_file()]
    if max(sizes) > policy['max_git_file_bytes'] or sum(sizes) > policy['max_cache_bytes']:
        raise ValueError('Compressed source cache exceeds the configured Git storage budget')
    (destination / 'storage.json').write_text(json.dumps({
        'schema': 2, 'code_sha': code_sha, 'cache_files': len(list(target.iterdir())),
        'compressed_bytes': sum(p.stat().st_size for p in target.iterdir()),
        'retained_releases': policy['keep_releases']}, separators=(',', ':')) + '\n')


def publish_cache(root, output, code_sha, policy):
    expected = remote_sha(root, 'data')
    with tempfile.TemporaryDirectory() as temp:
        destination = Path(temp)
        stage_cache(root, output, destination, code_sha, policy)
        commit = root_commit(root, destination, 'Replace compressed source cache')
        git(root, 'push', f'--force-with-lease=refs/heads/data:{expected}', 'origin',
            f'{commit}:refs/heads/data')
        print((destination / 'storage.json').read_text().strip(), flush=True)
    return commit


def unpack_cache(root, names, reader):
    configured = {s['id'] for s in json.loads((root / 'config/sources.json').read_text())['sources']}
    snapshots = []
    for name in names:
        path = Path(name)
        if path.parent != Path('source-cache') or not path.name.endswith('.json.gz'):
            raise ValueError(f'Unexpected cache path: {name}')
        if path.name[:-8] not in configured:
            continue
        with gzip.GzipFile(fileobj=io.BytesIO(reader(name))) as source:
            data = source.read(MAX_UNPACKED + 1)
        if len(data) > MAX_UNPACKED:
            raise ValueError(f'Oversized cached snapshot: {name}')
        obj = json.loads(data)
        if not isinstance(obj.get('rules'), dict) or not obj.get('last_success_at'):
            raise ValueError(f'Invalid cached snapshot: {name}')
        snapshots.append((path.name[:-3], data))
    if not snapshots:
        raise ValueError('The data branch has no usable configured source snapshots')
    destination = root / 'source-cache'
    destination.mkdir(exist_ok=True)
    for name, data in snapshots:
        (destination / name).write_bytes(data)
    return len(snapshots)


def restore_cache(root):
    if not remote_sha(root, 'data'):
        print('No data branch yet; using initial checkout snapshots if present', flush=True)
        return
    git(root, 'fetch', '--no-tags', '--depth=1', 'origin', 'refs/heads/data')
    names = git(root, 'ls-tree', '-r', '--name-only', 'FETCH_HEAD', 'source-cache/').splitlines()
    count = unpack_cache(root, names, lambda name: command(root, 'git', 'show',
                                                         f'FETCH_HEAD:{name}', binary=True))
    print(f'Restored {count} compressed source snapshots', flush=True)


def validate_payload(output):
    dist = output / 'dist'
    files = {p.name: p for p in dist.iterdir() if p.is_file()}
    suffixes = {'.lst', '.json', '.srs', '.mrs', '.dat', '.conf', '.txt', '.gz'}
    if (not 1 < len(files) <= 1000
            or any(n.startswith('.') or Path(n).suffix not in suffixes for n in files)):
        raise ValueError('Unexpected release payload')
    actual = {}
    for name, path in files.items():
        if not 0 < path.stat().st_size < 2 * 1024**3:
            raise ValueError(f'Empty or oversized release asset: {name}')
        with path.open('rb') as source:
            actual[name] = hashlib.file_digest(source, 'sha256').hexdigest()
    declared = dict(line.split('  ', 1)[::-1] for line in files['sha256sums.txt'].read_text().splitlines())
    if declared != {n: h for n, h in actual.items() if n != 'sha256sums.txt'}:
        raise ValueError('Release files do not match sha256sums.txt')
    return files, actual


def gh_json(root, endpoint, paginate=False):
    args = ['gh', 'api', endpoint]
    if paginate:
        args += ['--paginate', '--slurp']
    value = json.loads(command(root, *args))
    return [item for page in value for item in page] if paginate else value


def retention_candidates(releases, latest, keep, now=None):
    if keep < 1:
        raise ValueError('At least one successful release must be retained')
    now = now or datetime.now(timezone.utc)
    managed = [r for r in releases if MANAGED_TAG.fullmatch(r['tag_name'])]
    successful = sorted((r for r in managed if not r['draft'] and not r['prerelease']
                         and SCHEMA_MARKER in (r.get('body') or '')),
                        key=lambda r: r['published_at'], reverse=True)
    retained = {r['tag_name'] for r in successful[:keep]} | {latest}
    result = []
    for r in managed:
        if r['tag_name'] in retained:
            continue
        if r['draft']:
            legacy = successful and SCHEMA_MARKER not in (r.get('body') or '')
            expired = now - datetime.fromisoformat(r['created_at'].replace('Z', '+00:00')) > timedelta(days=2)
            if legacy or expired:
                result.append(r)
        elif successful and not r['prerelease']:
            result.append(r)
    return result


def cleanup(root, policy):
    repo = os.environ['GITHUB_REPOSITORY']
    releases = gh_json(root, f'repos/{repo}/releases?per_page=100', paginate=True)
    # Find latest without a 404 on the first ever publication.
    published = [r for r in releases if not r['draft'] and not r['prerelease']]
    latest = gh_json(root, f'repos/{repo}/releases/latest')['tag_name'] if published else None
    for release in retention_candidates(releases, latest, policy['keep_releases']):
        command(root, 'gh', 'release', 'delete', release['tag_name'], '--cleanup-tag', '--yes')
        print('Removed old release and tag:', release['tag_name'], flush=True)


def publish(root, output, policy):
    files, digests = validate_payload(output)
    code_sha = clean_main(root)
    publish_cache(root, output, code_sha, policy)
    tag = (datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-'
           + os.environ['GITHUB_RUN_ID'] + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '1'))
    notes = output / 'release-notes.md'
    manifest = json.loads((output / 'reports/manifest.json').read_text())
    notes.write_text(f"{SCHEMA_MARKER}\nCode: {code_sha}\nSets: {len(manifest['sets'])}. "
                     f"Retained successful releases: {policy['keep_releases']}.\n"
                     'All formats and diagnostics are release assets. Source cache is on data.\n')
    created = False
    try:
        command(root, 'gh', 'release', 'create', tag, '--target', code_sha, '--title',
                'Routing ' + tag, '--notes-file', str(notes), '--draft')
        created = True
        command(root, 'gh', 'release', 'upload', tag, *(str(files[n]) for n in sorted(files)))
        repo = os.environ['GITHUB_REPOSITORY']
        release = gh_json(root, f'repos/{repo}/releases/tags/{tag}')
        expected = {n: 'sha256:' + h for n, h in digests.items()}
        for attempt in range(3):
            assets = gh_json(root, f"repos/{repo}/releases/{release['id']}/assets?per_page=100", paginate=True)
            if {a['name']: a.get('digest') for a in assets} == expected:
                break
            if attempt < 2:
                time.sleep(5)
        else:
            raise ValueError('Uploaded release asset hashes do not match the build')
        command(root, 'gh', 'release', 'edit', tag, '--draft=false', '--latest')
    except BaseException:
        if created:
            # Never remove a release if the final publish request succeeded but its response was lost.
            release = gh_json(root, f"repos/{os.environ['GITHUB_REPOSITORY']}/releases/tags/{tag}")
            if release['draft']:
                command(root, 'gh', 'release', 'delete', tag, '--cleanup-tag', '--yes')
        raise
    print(f'Published {tag}: {len(files)} verified assets', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('restore', 'publish', 'cleanup'))
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, default=ROOT / '.cache/output')
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    policy = json.loads((root / 'config/storage.json').read_text())
    if args.operation == 'restore':
        restore_cache(root)
    elif args.operation == 'publish':
        publish(root, output, policy)
    else:
        cleanup(root, policy)


if __name__ == '__main__':
    main()
