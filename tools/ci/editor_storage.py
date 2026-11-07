#!/usr/bin/env python3
"""Prepare space on the disposable editor runner; never prune build/evidence paths.

The environment check prevents accidental local use, not hostile callers. This
is trusted CI preparation, not an OS security or test-acceptance boundary.
"""
import argparse
import json
import os
import stat
import subprocess


# Installed by actions/runner-images; neither SDK is used by the editor lane.
# No caller-supplied removal path, cache eviction or output cleanup is supported.
UNUSED_SDKS = ('/usr/share/dotnet', '/usr/local/lib/android')
CENSUS_PATHS = ('out/desktop', 'out/foundry',
                'out/ci-optimization/compiler-cache', 'target')


def emit(row):
    print(json.dumps({'schema_version': 1, **row}, sort_keys=True), flush=True)


def report(label):
    """Best-effort real observations; absence/errors never become space claims."""
    row = {'kind': 'editor_storage', 'label': label}
    try:
        disk = os.statvfs('.')
        row.update(available_bytes=disk.f_bavail * disk.f_frsize,
                   total_bytes=disk.f_blocks * disk.f_frsize,
                   available_inodes=disk.f_favail, total_inodes=disk.f_files)
    except OSError as error:
        row['space_error_errno'] = error.errno
    try:
        # Four fixed summary roots; no recursive listing or arbitrary paths.
        result = subprocess.run(['du', '-sk', '--', *CENSUS_PATHS],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, timeout=10, check=False)
        row.update(census_status='observed', census_exit=result.returncode,
                   census_kib=result.stdout[:2048],
                   census_truncated=len(result.stdout) > 2048)
    except (OSError, subprocess.TimeoutExpired) as error:
        row['census_status'] = type(error).__name__
    emit(row)


def prepare():
    required = {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux',
                'EDITOR_RUNNER_ENVIRONMENT': 'github-hosted'}
    if any(os.environ.get(key) != value for key, value in required.items()):
        raise RuntimeError('SDK removal requires a disposable GitHub-hosted Linux runner')
    report('before-preparation')
    for path in UNUSED_SDKS:
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            emit({'kind': 'unused_editor_sdk', 'path': path, 'status': 'absent'})
            continue
        if not stat.S_ISDIR(mode):
            raise RuntimeError('unused SDK path must be a real directory: ' + path)
        subprocess.run(['sudo', '-n', 'rm', '--recursive', '--force',
                        '--one-file-system', '--', path], check=True)
        emit({'kind': 'unused_editor_sdk', 'path': path, 'status': 'removed'})
    report('after-preparation')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'before-editor', 'after-editor'))
    args = parser.parse_args(argv)
    if args.action == 'prepare':
        prepare()
    else:
        report(args.action)


if __name__ == '__main__':
    main()
