#!/usr/bin/env python3
"""Fixed operator observations for a failed canonical agent lane, never acceptance.

Run `begin` before the unchanged lane and `failure` in a separate CI failure step.
Diagnostic failure returns zero so it cannot replace that already failed step.
No container is created, started, inspected, removed, retried or reconciled here.
"""
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

import selected_test_runner as runner


OUTPUT = Path('out/agent-runner-diagnostics')
SCOPE = 'canonical_agent_lane_window_not_request_window'
FILE_LIMIT = 262144
METADATA_LIMIT = 262144
WINDOW_SECONDS = 6 * 60 * 60
PROC_PATHS = ('/proc/loadavg', '/proc/meminfo', '/proc/pressure/cpu',
              '/proc/pressure/io', '/proc/pressure/memory',
              '/sys/fs/cgroup/cpu.stat', '/sys/fs/cgroup/memory.events')


def stamp():
    return {'utc': datetime.now(timezone.utc).isoformat(timespec='microseconds'),
            'monotonic_ns': time.monotonic_ns()}


def small_read(path, limit):
    """Never follow a leaf link or block opening a FIFO; keep an explicit prefix."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                return {'status': 'unavailable', 'error': 'nonregular_file'}
            raw = source.read(limit + 1)
        return {'status': 'observed', 'text': raw[:limit].decode(errors='replace'),
                'prefix_bytes': min(len(raw), limit), 'truncated': len(raw) > limit}
    except OSError as error:
        return {'status': 'unavailable', 'error_errno': error.errno}


def resources():
    filesystems = []
    for path in ('.', '/var/lib/docker'):
        row = {'path': path}
        try:
            value = os.statvfs(path)
            row.update(available_bytes=value.f_bavail * value.f_frsize,
                       total_bytes=value.f_blocks * value.f_frsize,
                       available_inodes=value.f_favail, total_inodes=value.f_files)
        except OSError as error:
            row['error_errno'] = error.errno
        filesystems.append(row)
    return {'scope': 'host_snapshots_not_request_causality', 'filesystems': filesystems,
            'proc': {path: small_read(path, 4096) for path in PROC_PATHS}}


def directory():
    # Fixed relative namespace; refuse symlink components and preserve prior files.
    for path in (OUTPUT.parent, OUTPUT):
        path.mkdir(mode=0o700, exist_ok=True)
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise ValueError('diagnostic directory is not a real directory')


def write(name, row):
    raw = (json.dumps(row, sort_keys=True) + '\n').encode()
    if len(raw) > METADATA_LIMIT:
        raise ValueError('diagnostic metadata limit')
    fd = os.open(OUTPUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)


def read_json(name):
    observed = small_read(OUTPUT / name, METADATA_LIMIT)
    if observed['status'] != 'observed' or observed['truncated']:
        raise ValueError('missing, nonregular or oversized diagnostic record')
    return json.loads(observed['text'])


def window(begin, end):
    if (type(begin) is not dict or type(begin.get('schema_version')) is not int or begin['schema_version'] != 1
            or begin.get('kind') != 'agent_runner_begin' or begin.get('scope') != SCOPE
            or begin.get('acceptance') is not False):
        raise ValueError('invalid begin identity')
    start = begin.get('started')
    parsed = []
    for value in (start, end):
        if (type(value) is not dict or set(value) != {'utc', 'monotonic_ns'}
                or type(value['monotonic_ns']) is not int or value['monotonic_ns'] < 0
                or type(value['utc']) is not str or len(value['utc']) != 32):
            raise ValueError('invalid window stamp')
        instant = datetime.fromisoformat(value['utc'])
        if (instant.utcoffset() is None or instant.utcoffset().total_seconds() != 0
                or instant.isoformat(timespec='microseconds') != value['utc']):
            raise ValueError('noncanonical UTC stamp')
        parsed.append(instant)
    wall = (parsed[1] - parsed[0]).total_seconds()
    monotonic = (end['monotonic_ns'] - start['monotonic_ns']) / 1_000_000_000
    if not 0 <= wall <= WINDOW_SECONDS or not 0 <= monotonic <= WINDOW_SECONDS:
        raise ValueError('backward or exhausted diagnostic window')
    return start


def commands(start, end):
    prefix = ['/usr/bin/prlimit', '--fsize=262144:262144', '--']
    def journal_time(value):
        return value['utc'].replace('T', ' ').replace('+00:00', ' UTC')
    return (
        ('journal', prefix + ['/usr/bin/journalctl', '--no-pager', '--utc',
            '--output=short-iso-precise', '--unit=docker.service', '--unit=containerd.service',
            '--lines=256', '--since', journal_time(start), '--until', journal_time(end)]),
        ('events', prefix + ['/usr/bin/docker', 'events', '--since', start['utc'],
            '--until', end['utc'], '--filter', 'type=container', '--format', '{{json .}}']),
    )


def log_observation(name):
    path = OUTPUT / name
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > FILE_LIMIT:
            return {'path': name, 'status': 'unavailable', 'error': 'nonregular_or_over_limit',
                    'observed_bytes': metadata.st_size, 'at_limit': metadata.st_size >= FILE_LIMIT}
        observed = small_read(path, FILE_LIMIT)
        if observed['status'] != 'observed':
            return {'path': name, **observed, 'at_limit': False}
        # Hash the original bounded bytes, not their replacement-decoded rendering.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as source:
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (metadata.st_dev, metadata.st_ino, metadata.st_size):
                raise ValueError('diagnostic log changed')
            raw = source.read(FILE_LIMIT + 1)
        if len(raw) != metadata.st_size:
            raise ValueError('diagnostic log size changed')
        return {'path': name, 'status': 'observed' if raw else 'empty',
                'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                'at_limit': len(raw) >= FILE_LIMIT}
    except (OSError, ValueError) as error:
        return {'path': name, 'status': 'unavailable', 'error': type(error).__name__, 'at_limit': False}


def query(label, argv):
    record = None
    failure = None
    try:
        record = runner.run_owned(argv, OUTPUT, label, work_seconds=5)
    except Exception as error:
        failure = type(error).__name__
        try:
            record = read_json(label + '.command.json')
        except (OSError, ValueError, TypeError):
            pass
    stdout = log_observation(label + '.stdout')
    stderr = log_observation(label + '.stderr')
    cleanup = bool(type(record) is dict and (record.get('pid') is None
                   or (record.get('reaped') is True and record.get('group_stop_before_reap') is True)))
    complete = bool(not failure and cleanup and type(record.get('pid')) is int and record['pid'] > 0
                    and type(record.get('exit_code')) is int and record['exit_code'] == 0
                    and all(log['status'] in ('observed', 'empty') and not log['at_limit']
                            for log in (stdout, stderr)))
    return {'kind': label, 'status': 'observed' if complete else 'error', 'complete': complete,
            'exception_type': failure, 'cleanup_observed': cleanup, 'receipt': record,
            'stdout': stdout, 'stderr': stderr,
            'history_complete': False, 'absence_or_cause_proven': False}


def begin():
    directory()
    if any(os.path.lexists(OUTPUT / name) for name in ('begin.json', 'begin.attempt')):
        # Preserve the first capture, but never attribute it to a later lane.
        write('begin.rejected.json', {'kind': 'duplicate_begin', 'acceptance': False})
        raise ValueError('begin already attempted')
    fd = os.open(OUTPUT / 'begin.attempt', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    os.close(fd)
    started = stamp()
    write('begin.json', {'schema_version': 1, 'kind': 'agent_runner_begin', 'acceptance': False,
                        'scope': SCOPE, 'started': started, 'resources': resources()})


def failure():
    directory()
    # Claim this one diagnostic attempt before any subprocess; a later invocation
    # must not overwrite evidence or issue another query after a partial failure.
    fd = os.open(OUTPUT / 'failure.attempt', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    os.close(fd)
    ended = stamp()
    row = {'schema_version': 1, 'kind': 'agent_runner_failure', 'acceptance': False,
           'scope': SCOPE, 'ended': ended, 'resources': resources(), 'queries': [],
           'window_status': 'unavailable', 'started': None}
    try:
        if os.path.lexists(OUTPUT / 'begin.rejected.json'):
            raise ValueError('begin reuse refused')
        row['started'] = window(read_json('begin.json'), ended)
    except (OSError, ValueError, TypeError, KeyError) as error:
        row['window_error'] = type(error).__name__
    else:
        row['window_status'] = 'observed'
        for label, argv in commands(row['started'], ended):
            if row['queries'] and not row['queries'][-1]['cleanup_observed']:
                row['queries'].append({'kind': label, 'status': 'not_attempted_prior_cleanup_uncertain'})
                break
            row['queries'].append(query(label, argv))
    write('failure.json', row)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('begin', 'failure'))
    args = parser.parse_args(argv)
    try:
        (begin if args.action == 'begin' else failure)()
    except Exception as error:
        # No exception text, environment, arbitrary paths or successful verdict.
        try:
            print(json.dumps({'kind': 'agent_runner_diagnostic_error', 'acceptance': False,
                              'action': args.action, 'error_type': type(error).__name__}), file=sys.stderr)
        except Exception:
            pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
