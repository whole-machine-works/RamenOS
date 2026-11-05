#!/usr/bin/env python3
"""Capture the eight existing editor stages once, immediately after execution.

These are source-bound command and semantic-report receipts, not cached test
results. The runtime gate verifies them on the same immutable candidate.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess

import selected_test_runner as runner

SPECS = {
    'desktop-launch': ('D30Launch17', 'desktop/ui1-0/result.json'),
    'desktop-editor-host': ('D30Volatile13', 'desktop/ui1-1a/result.json'),
    'desktop-editor-store': ('D30Store7Reader16', 'desktop/ui1-1b.*/evidence/result.json'),
    'editor-native-read': ('D30NativeRead9', 'desktop/native-read-*/evidence/result.json'),
    'editor-native-preview': ('D30NativePreview5', 'desktop/native-preview-read-*/evidence/result.json'),
    'desktop-editor-task': ('D30Original18Reader93', 'desktop/native-task-source.*/run/process/result.json'),
    'editor-adapter-migration': ('D30Adapter4', 'foundry/editor-adapter-migration/run.*'),
    'editor-reliability': ('D30Reliability13', 'foundry/editor-reliability/run.*/result.json'),
}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            digest.update(block)
    return digest.hexdigest()


def ref(path):
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), 'regular absolute receipt')
    return {'path': str(path), 'sha256': sha(path)}


def publish(path, value):
    with path.open('x') as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write('\n')


def source_rows(repo):
    names = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=repo)
    rows = []
    for name in sorted(set(os.fsdecode(n) for n in names.split(b'\0') if n)):
        path = repo / name
        if path.is_symlink():
            continue  # The canonical lane separately fingerprints symlink targets.
        require(path.is_file(), 'missing candidate source: ' + name)
        rows.append({'path': name, 'bytes': path.stat().st_size, 'sha256': sha(path)})
    require(0 < len(rows) <= 1024, 'bounded complete candidate source inventory')
    return rows


def source_links(repo):
    names = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=repo)
    return [{'path': name, 'target': os.readlink(repo / name)}
            for name in sorted(set(os.fsdecode(n) for n in names.split(b'\0') if n))
            if (repo / name).is_symlink()]


def tree_rows(root):
    result = []
    count = size = 0
    for directory, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            require(not (Path(directory) / name).is_symlink(), 'linked retained directory')
        for name in names:
            path = Path(directory) / name
            count += 1
            require(count <= 20000 and path.is_file() and not path.is_symlink(), 'bounded regular retained closure')
            size += path.stat().st_size
            require(size <= 2 * 1024**3, 'retained closure bytes')
            result.append({'path': str(path.relative_to(root)), 'bytes': path.stat().st_size, 'sha256': sha(path)})
    return sorted(result, key=lambda row: row['path'])


def create(repo):
    parent = repo / 'out/foundry/editor-process-stages'
    parent.mkdir(parents=True, exist_ok=True)
    batch = parent / secrets.token_hex(16)
    batch.mkdir(mode=0o700)
    publish(batch / 'source.json', source_rows(repo))
    tools = {name: subprocess.check_output([name, '--version'], cwd=repo).decode().strip()
             for name in ('rustc', 'cargo')}
    publish(batch / 'batch.json', {'schema_version': 1, 'repo': str(repo),
            'run_nonce': batch.name, 'source_manifest': ref(batch / 'source.json'),
            'lockfile_sha256': sha(repo / 'Cargo.lock'), 'source_links': source_links(repo), 'toolchain': tools,
            'toolchain_manifest_sha256': sha(repo / 'rust-toolchain.toml')})
    return batch


def matches(repo, stage):
    return {p: (p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_size)
            for p in (repo / 'out').glob(SPECS[stage][1]) if not p.is_symlink()}


def copy_tree(source, target):
    """Copy diagnostics only; reject links and bound before copying each leaf."""
    target.mkdir(mode=0o700)
    files = size = 0
    for directory, directories, names in os.walk(source, followlinks=False):
        directories.sort()
        names.sort()
        for name in directories:
            path = Path(directory) / name
            require(not path.is_symlink(), 'linked evidence directory')
            (target / path.relative_to(source)).mkdir(mode=0o700)
        for name in names:
            path = Path(directory) / name
            require(path.is_file() and not path.is_symlink(), 'nonregular stage evidence')
            files += 1
            size += path.stat().st_size
            require(files <= 20000 and size <= 2 * 1024**3, 'stage evidence copy budget')
            destination = target / path.relative_to(source)
            shutil.copyfile(path, destination)
            require(sha(path) == sha(destination), 'stage evidence changed during copy')


def stage(repo, batch, name, argv, environment):
    require(name in SPECS, 'known editor stage')
    output = batch / name
    output.mkdir(mode=0o700)
    before = matches(repo, name)
    timings = output / 'timings'
    command = ['python3', str(repo / 'tools/ci/stage_timer.py'), '--directory',
               str(timings), '--label', name, '--', *argv]
    previous = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(environment)
        owned = runner.run_owned(command, output, 'stage', work_seconds=600)
    finally:
        os.environ.clear()
        os.environ.update(previous)
    print((output / 'stage.stdout').read_text(), end='', flush=True)
    print((output / 'stage.stderr').read_text(), end='', flush=True)
    if owned['exit_code'] != 0:
        return owned['exit_code']
    actual = list(timings.glob('*.json'))
    require(len(actual) == 1, 'one actual inner timing receipt')
    inner = json.loads(actual[0].read_bytes())
    require(inner['argv'] == list(argv) and inner['status'] == 'PASS'
            and inner['exit_code'] == inner['child_returncode'] == 0
            and inner['wait_reaped'] is True and inner['cleanup_uncertain'] is False,
            'actual inner command must exit and reap successfully')
    after = matches(repo, name)
    fresh = [p for p, identity in after.items() if before.get(p) != identity]
    require(len(fresh) == 1, 'one fresh semantic output for ' + name)
    if fresh[0].is_dir():
        source = fresh[0]
        relative_report = Path('adapter-result.json')
    else:
        source = fresh[0].parents[2] if name == 'desktop-editor-task' else fresh[0].parent.parent if fresh[0].parent.name == 'evidence' else fresh[0].parent
        relative_report = fresh[0].relative_to(source)
    copy_tree(source, output / 'evidence')
    publish(output / 'evidence-inventory.json', tree_rows(output / 'evidence'))
    report = output / 'evidence' / relative_report
    if name == 'editor-adapter-migration':
        publish(report, {'status': 'PASS', 'scope': 'unchanged adapter classifier exit',
                'source_sha256': {r['path']: r['sha256'] for r in source_rows(repo)},
                'artifact_sha256': {p.name: sha(p) for p in (output / 'evidence').iterdir() if p.is_file()}})
    inventory = output / 'evidence-inventory.json'
    inventory.unlink()
    publish(inventory, tree_rows(output / 'evidence'))
    value = json.loads(report.read_bytes())
    require(value.get('status', value.get('outcome')) == 'PASS', 'actual semantic reader PASS')
    # Retain the exact manifest bytes whose digest the semantic reader used.
    manifest = output / 'semantic-source.json'
    if 'source_manifest_sha256' in value:
        pin = value['source_manifest_sha256']
        candidates = [p for parent in (source, source.parent, source.parent.parent)
                      for p in parent.glob('*source*.json') if p.is_file() and not p.is_symlink() and sha(p) == pin]
        require(bool(candidates), 'actual semantic source manifest retained')
        shutil.copyfile(candidates[0], manifest)
        rows = json.loads(manifest.read_bytes())
    else:
        rows = [{'path': n, 'bytes': (repo / n).stat().st_size, 'sha256': h}
                for n, h in sorted(value['source_sha256'].items())]
        publish(manifest, rows)
    for row in rows:
        source_name = row.get('path', row.get('relative_path', ''))
        require(type(source_name) is str and source_name and not Path(source_name).is_absolute()
                and '..' not in Path(source_name).parts, 'relative semantic source')
        path = repo / source_name
        require(not path.is_symlink() and sha(path) == row['sha256'], 'semantic source matches fixed candidate')
    child = {**ref(report), 'source_manifest': ref(output / 'semantic-source.json'),
             'source_manifest_sha256': sha(output / 'semantic-source.json')}
    if 'source_manifest_sha256' in value:
        require(child['source_manifest_sha256'] == value['source_manifest_sha256'], 'exact original source manifest serialization')
    nonce = value.get('run_nonce', value.get('provenance', {}).get('nonce'))
    if nonce is not None:
        child['child_run_nonce'] = nonce
    publish(output / 'receipt.json', {'id': SPECS[name][0], 'argv': list(argv),
            'exit_code': 0, 'wait_reaped': True, 'cleanup_uncertain': False,
            'evidence_inventory': ref(output / 'evidence-inventory.json'),
            'outer_command': ref(output / 'stage.command.json'), 'inner_command': ref(actual[0]),
            'stdout': ref(output / 'stage.stdout'), 'stderr': ref(output / 'stage.stderr'),
            'artifacts': [], 'gate_reports': [child]})
    return 0


def verify(repo, batch):
    """Revalidate the full fresh batch before a runtime gate consumes any row."""
    header = json.loads((batch / 'batch.json').read_bytes())
    require(header['schema_version'] == 1 and header['repo'] == str(repo)
            and re.fullmatch('[0-9a-f]{32}', header['run_nonce'])
            and header['run_nonce'] == batch.name, 'exact fresh batch identity')
    require(ref(batch / 'source.json') == header['source_manifest'], 'candidate manifest intact')
    require(json.loads((batch / 'source.json').read_bytes()) == source_rows(repo), 'candidate source unchanged')
    require(source_links(repo) == header['source_links'], 'candidate symlink targets unchanged')
    require(sha(repo / 'Cargo.lock') == header['lockfile_sha256']
            and sha(repo / 'rust-toolchain.toml') == header['toolchain_manifest_sha256'], 'fixed lock and toolchain')
    for tool, version in header['toolchain'].items():
        require(tool in ('cargo', 'rustc') and subprocess.check_output([tool, '--version'], cwd=repo).decode().strip() == version, 'actual toolchain unchanged')
    probes = []
    for name, (identity, _) in SPECS.items():
        output = batch / name
        row = json.loads((output / 'receipt.json').read_bytes())
        require(row['id'] == identity and row['exit_code'] == 0 and row['wait_reaped'] is True
                and row['cleanup_uncertain'] is False, 'successful actual stage receipt')
        for field in ('outer_command', 'inner_command', 'stdout', 'stderr'):
            recorded = row[field]
            path = Path(recorded['path'])
            require(path.is_relative_to(output) and ref(path) == recorded, 'stage command and logs intact')
        inventory = row['evidence_inventory']
        require(ref(Path(inventory['path'])) == inventory and Path(inventory['path']).parent == output, 'retained closure inventory intact')
        require(tree_rows(output / 'evidence') == json.loads(Path(inventory['path']).read_bytes()), 'exact copied raw closure unchanged')
        outer = json.loads(Path(row['outer_command']['path']).read_bytes())
        inner = json.loads(Path(row['inner_command']['path']).read_bytes())
        require(outer['exit_code'] == 0 and outer['reaped'] is True and outer['group_stop_before_reap'] is True
                and inner['argv'] == row['argv'] and inner['child_returncode'] == inner['exit_code'] == 0
                and inner['wait_reaped'] is True and inner['cleanup_uncertain'] is False, 'both actual native command owners reaped')
        require(outer['argv'][-len(row['argv']):] == row['argv'], 'exact nested stage argv')
        for gate in row['gate_reports']:
            require(ref(Path(gate['path'])) == {k: gate[k] for k in ('path', 'sha256')}
                    and ref(Path(gate['source_manifest']['path'])) == gate['source_manifest'], 'retained semantic evidence intact')
            value = json.loads(Path(gate['path']).read_bytes())
            require(value.get('status', value.get('outcome')) == 'PASS', 'actual semantic reader accepted')
            for name, pin in value.get('artifact_sha256', {}).items():
                path = Path(name)
                require(not path.is_absolute() and '..' not in path.parts
                        and sha(Path(gate['path']).parent / path) == pin, 'semantic raw closure intact')
        probes.append(row)
    require({p.name for p in batch.iterdir()} == {'batch.json', 'source.json', *SPECS}, 'exact full stage batch inventory')
    return header, probes
