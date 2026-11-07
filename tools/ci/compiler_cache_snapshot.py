#!/usr/bin/env python3
"""Retain compiler targets from one verified successful editor batch.

This opt-in CI storage operation supplies no acceptance evidence. Retirement is
delegated to the existing bounded, locked cache control; stage receipts remain
untouched. A race during retirement fails closed and records partial progress.
"""
import hashlib
import json
import os
from pathlib import Path
import re

import compiler_cache_control as control
import editor_process_stage_receipts as receipts

REPORTS = {
    'editor-native-read': ('D30NativeRead9', {
        'exclusion-desktop': ['desktop_v0_dev'],
        'exclusion-store': ['editor_store_v0_dev'], 'enabled': ['editor_native_read_v0_dev']}),
    'editor-native-preview': ('D30NativePreview5', {
        'exclusion-desktop': ['editor_native_read_v0_dev'],
        'exclusion-store': ['editor_native_read_v0_dev'], 'enabled': ['editor_native_preview_v0_dev']}),
    'desktop-editor-task': ('D30Original18Reader93', {
        'exclusion-app': [], 'enabled-app': ['host_native_save_v0_dev'], 'manifest-verifier': ['std']}),
    'editor-reliability': ('D30Reliability13', {
        'enabled-artifact_editor': ['host_native_save_v0_dev'],
        'enabled-store_service': ['editor_native_save_v0_dev']}),
}
REPORT_PATHS = {
    'editor-native-read': 'evidence/evidence/result.json',
    'editor-native-preview': 'evidence/evidence/result.json',
    'desktop-editor-task': 'evidence/run/process/result.json',
    'editor-reliability': 'evidence/result.json',
}


def require(ok, message):
    if not ok:
        raise ValueError('compiler snapshot: ' + message)


def references(repo, batch, probes):
    """Select the exact source-bound reports, never discover batches or use mtimes."""
    keep = {}
    for stage, (identity, expected) in REPORTS.items():
        selected = [row for row in probes if row['id'] == identity]
        require(len(selected) == 1 and len(selected[0]['gate_reports']) == 1, 'one semantic report per cache consumer')
        gate = selected[0]['gate_reports'][0]
        path = batch / stage / REPORT_PATHS[stage]
        require(gate['path'] == str(path) and receipts.ref(path) == {k: gate[k] for k in ('path', 'sha256')},
                'exact unchanged copied semantic report')
        manifest = batch / stage / 'semantic-source.json'
        require(receipts.ref(manifest) == gate['source_manifest'], 'exact semantic source manifest')
        value = json.loads(path.read_bytes())
        require(value.get('status', value.get('outcome')) == 'PASS'
                and value['source_manifest_sha256'] == gate['source_manifest']['sha256'], 'successful source-bound report')
        metadata = value['provenance']['compiler_cache'] if stage == 'desktop-editor-task' else value['compiler_cache']
        require(metadata['enabled'] is True and metadata['cached_acceptance'] is False, 'enabled compiler-only cache')
        phases = metadata['phases']
        require(type(phases) is list and len(phases) == len(expected), 'complete phase inventory')
        seen = set()
        for phase in phases:
            name = phase['phase']; key = phase['key_sha256']
            require(type(name) is str and name in expected and name not in seen, 'exact unique compiler phase')
            seen.add(name)
            require(type(key) is str and re.fullmatch('[a-f0-9]{64}', key) and key not in keep, 'unique exact compiler key')
            require(type(phase['schema_version']) is int and phase['schema_version'] == 1
                    and phase['enabled'] is True and phase['admitted'] is True
                    and phase['scope'] == 'acceptance' and phase['cached_acceptance'] is False
                    and phase['exclusive_lock_held'] is True and phase['inflight_marker_admitted'] is True
                    and type(phase['hit']) is bool and phase['features'] == expected[name]
                    and phase['target'] == str(control.root_path(repo, 'acceptance') / key / 'target'),
                    'admitted acceptance compiler phase')
            keep[key] = {'phase': name, 'features': expected[name], 'manifest_sha256': value['source_manifest_sha256']}
    return keep


def check_current(repo, row, expected, lock_sha):
    """Recheck the current entry under existing allocation/owner locks."""
    root = control.cache.directory(control.root_path(repo, 'acceptance'), private=True)
    allocation = child = owner = None
    try:
        allocation = control.existing_lock(root, '.allocation.lock')
        child = os.open(row['key'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        owner = control.existing_lock(child, 'owner.lock')
        raw, context = control.entry_context(child, repo, 'acceptance', row['key'])
        require(hashlib.sha256(raw).hexdigest() == row['context_sha256'], 'current context unchanged since inspection')
        require(set(control.bounded_names(child, 8)) == {'context.json', 'owner.lock', 'target'}, 'completed current entry')
        require(all(context[k] == v for k, v in expected.items())
                and context['lock_sha256'] == lock_sha, 'current context matches source and compiler phase')
    finally:
        for fd in (owner, child, allocation, root):
            if fd is not None:
                os.close(fd)


def snapshot(repo, batch):
    repo, batch = Path(repo), Path(batch)
    require(repo.is_absolute() and batch.is_absolute()
            and batch.parent == repo / 'out/foundry/editor-process-stages'
            and re.fullmatch('[a-f0-9]{32}', batch.name), 'exact explicit stage batch')
    header, probes = receipts.verify(repo, batch)
    keep = references(repo, batch, probes)
    inspected = control.inspect_cache(repo, 'acceptance')
    rows = inspected['entries']
    require(inspected['available'] and len({row['key'] for row in rows}) == len(rows), 'available unique compiler entries')
    require(all(row['state'] == 'completed' and row['retirable'] for row in rows),
            'all entries completed with known ownership')
    by_key = {row['key']: row for row in rows}
    require(keep.keys() <= by_key.keys(), 'all current referenced targets present')
    for key, expected in keep.items():
        check_current(repo, by_key[key], expected, header['lockfile_sha256'])
    kept = [by_key[key] for key in sorted(keep)]
    stale = [by_key[key] for key in sorted(by_key.keys() - keep.keys())]
    report = {'schema_version': 1, 'status': 'REFUSED', 'stage_batch': str(batch),
              'scope': 'acceptance', 'cached_acceptance': False, 'evidence_removed': False,
              'kept': kept, 'retired': [], 'kept_logical_bytes': sum(row['logical_bytes'] for row in kept),
              'retired_logical_bytes': 0}
    # A sibling is covered by the existing stage-artifact upload without changing
    # the exact verified batch inventory. Exclusive creation prevents report reuse.
    with batch.with_suffix('.cache-snapshot.json').open('x') as output:
        try:
            for row in stale:
                control.retire(repo, 'acceptance', row['key'], row['context_sha256'])
                report['retired'].append(row)
                report['retired_logical_bytes'] += row['logical_bytes']
            report['status'] = 'PASS'
        finally:
            json.dump(report, output, sort_keys=True, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
    print('FOUNDRY_CACHE_SNAPSHOT: kept=' + str(len(kept)) + ' retired=' + str(len(stale))
          + ' retired_logical_bytes=' + str(report['retired_logical_bytes']), flush=True)
    return report
