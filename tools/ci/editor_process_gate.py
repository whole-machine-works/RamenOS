#!/usr/bin/env python3
"""Fresh Linux editor-process acceptance over a fixed source candidate.

Existing editor stages are consumed from the same lane's immediate receipts or
executed once when invoked standalone. Diagnostic recordings alone never PASS.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess

import editor_process_stage_receipts as stages
import selected_test_runner as runner

ROOT = Path(__file__).resolve().parents[2]
FEATURE = 'host_editor_process_assertions_v0_dev'


def rust_cases(path):
    return sorted(set(re.findall(r'#\[test\]\s*fn\s+(\w+)\s*\(', path.read_text())))


def selected(probe, names):
    text = Path(probe['stdout']['path']).read_text()
    structured = []
    for line in text.splitlines():
        if line.startswith('{'):
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and value.get('type') in ('suite', 'test'):
                structured.append(value)
    if structured:
        suites = [row for row in structured if row['type'] == 'suite']
        starts = [row['name'] for row in structured if row['type'] == 'test' and row.get('event') == 'started']
        outcomes = [row for row in structured if row['type'] == 'test' and row.get('event') in ('ok', 'failed', 'ignored')]
        stages.require(len(suites) == 2 and suites[0].get('event') == 'started'
                       and suites[0].get('test_count') == len(names)
                       and suites[1].get('event') == 'ok' and suites[1].get('passed') == len(names)
                       and suites[1].get('failed') == suites[1].get('ignored') == 0
                       and sorted(starts) == sorted(names) and len(outcomes) == len(names)
                       and all(row['event'] == 'ok' for row in outcomes), 'exact structured selected test outcomes')
        actual = [row['name'] for row in outcomes]
    else:
        actual = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ok$', text, re.M)
    stages.require(sorted(actual) == sorted(names) and len(actual) == len(set(actual)), 'exact selected test outcomes')
    diagnostic = Path(probe['stderr']['path']).read_text()
    stages.require('FAILED' not in text and 'INCOMPLETE' not in text
                   and 'INCOMPLETE' not in diagnostic, 'complete actual test outcomes')
    probe.update(selected=sorted(names), passed=sorted(actual))


class Gate:
    def __init__(self, repo, output, batch):
        self.repo, self.output = repo, output
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.nonce = secrets.token_hex(16)
        stages.publish(output / 'source.json', stages.source_rows(repo))
        self.source = stages.ref(output / 'source.json')
        self.links = stages.source_links(repo)
        self.lock = stages.sha(repo / 'Cargo.lock')
        self.probes = []
        self.batch = batch
        self.record = output / 'gate-record.json'
        for key, name in [('RAMEN_NATIVE_TASK_EVIDENCE', 'parent-io'), ('RAMEN_PROCESS_EVIDENCE', 'process-io')]:
            path = output / name
            path.mkdir(mode=0o700)
            os.environ[key] = str(path)
        os.environ.update(RAMEN_NATIVE_TASK_RUN_NONCE=self.nonce,
                          RAMEN_PROCESS_RUN_NONCE=self.nonce,
                          RAMEN_PROCESS_GATE_RECORD=str(self.record))
        self.save()

    def save(self):
        value = {'schema_version': 1, 'phase': 'runtime', 'run_nonce': self.nonce,
                 'repo': str(self.repo), 'source_manifest': self.source,
                 'lockfile': {'before': self.lock, 'after': stages.sha(self.repo / 'Cargo.lock')},
                 'probes': self.probes}
        temporary = self.output / 'gate-record.tmp'
        temporary.write_text(json.dumps(value, indent=2) + '\n')
        temporary.replace(self.record)

    def run(self, identity, argv, expected=0):
        actual = runner.run_owned(argv, self.output, identity, work_seconds=600)
        probe = {'id': identity, 'argv': argv, 'exit_code': actual['exit_code'],
                 'wait_reaped': actual['reaped'], 'cleanup_uncertain': 'cleanup_error' in actual,
                 'stdout': stages.ref(self.output / (identity + '.stdout')),
                 'stderr': stages.ref(self.output / (identity + '.stderr')),
                 'artifacts': [], 'gate_reports': []}
        self.probes.append(probe)
        self.save()
        stages.require(actual['exit_code'] == expected and actual['reaped'], identity + ' unexpected exit')
        return probe

    def build(self, identity, feature, target, child=False):
        # Distinct normal/assertion child targets prevent one build replacing
        # the executable selected by the other build's real Cargo receipt.
        argv = ['cargo', 'build', '--locked', '-p', 'artifact_editor', '--no-default-features',
                '--features', feature, '--message-format=json']
        if child:
            argv += ['--bin', 'editor-process', '--target-dir', str(self.repo / 'target' / identity)]
        else:
            argv += ['--lib']
        probe = self.run(identity, argv)
        rows = runner.json_rows(Path(probe['stdout']['path']).read_text())
        artifacts = [r for r in rows if r.get('reason') == 'compiler-artifact'
                     and r['target']['name'] == target and (r.get('executable') if child else r['target']['kind'] == ['lib'])]
        stages.require(len(artifacts) == 1, 'one Cargo-selected artifact')
        row = artifacts[0]
        path = Path(row['executable'] if child else row['filenames'][0])
        kind = 'production_child' if feature == 'host_editor_process_child_v0_dev' else 'assertion_child' if child else 'parent'
        artifact = {**stages.ref(path), 'kind': kind, 'features': row['features']}
        probe['artifacts'] = [artifact]
        self.save()
        return path, artifact

    def api_absent(self, identity, body, features, symbol, code='E0599'):
        packet = self.output / identity
        packet.mkdir()
        (packet / 'src').mkdir()
        (packet / 'src/lib.rs').write_text(body + '\n')
        feature_text = ','.join(json.dumps(f) for f in features)
        (packet / 'Cargo.toml').write_text('[package]\nname="process_api_absence_probe"\nversion="0.0.0"\nedition="2021"\n[workspace]\n[dependencies]\ndesktop_service={path=' + json.dumps(str(self.repo / 'services/desktop')) + ',default-features=false,features=[' + feature_text + ']}\n')
        manifest = str(packet / 'Cargo.toml')
        self.run(identity + 'Lock', ['cargo', 'generate-lockfile', '--offline', '--manifest-path', manifest])
        probe = self.run(identity, ['cargo', 'check', '--locked', '--offline', '--manifest-path', manifest,
                                  '--target-dir', str(self.repo / 'target'), '--message-format=json'], 101)
        probe['artifacts'] = [{**stages.ref(packet / 'src/lib.rs'), 'kind': 'api_probe_source'},
                              {**stages.ref(packet / 'Cargo.toml'), 'kind': 'api_probe_manifest'},
                              {**stages.ref(packet / 'Cargo.lock'), 'kind': 'api_probe_lock'}]
        self.save()
        errors = [r['message'] for r in runner.json_rows(Path(probe['stdout']['path']).read_text())
                  if r.get('reason') == 'compiler-message' and r['message']['level'] == 'error']
        stages.require(len(errors) == 1 and errors[0]['code']['code'] == code
                       and symbol in errors[0]['message'], 'exact missing API compiler diagnostic')

    def unchanged(self):
        header, probes = stages.verify(self.repo, self.batch)
        from ci_lanes import EXTENDED
        commands = {s.name: list(s.argv) for s in EXTENDED}
        for name, probe in zip(stages.SPECS, probes):
            stages.require(probe['argv'] == commands[name], 'unchanged stage exact command')
            report = json.loads(Path(probe['gate_reports'][0]['path']).read_bytes())
            names = report.get('required_cases', report.get('behavior_cases', report.get('cases')))
            if name == 'desktop-editor-task':
                names = rust_cases(self.repo / 'apps/artifact_editor/tests/native_task.rs')
            elif name == 'editor-adapter-migration':
                names = rust_cases(self.repo / 'services/desktop/tests/editor_adapter_migration.rs') + rust_cases(self.repo / 'apps/artifact_editor/tests/editor_adapter_migration.rs')
            elif name == 'editor-reliability':
                names = [n for t in report['targets'] for n in t['cases']]
            stages.require(type(names) is list and names and len(names) == len(set(names)), 'actual existing selected inventory')
            probe.update(selected=sorted(names), passed=sorted(names), stage_batch_nonce=header['run_nonce'])
            self.probes.append(probe)
        self.save()


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--stage-batch', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    stages.require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Linux x86_64 runtime required')
    os.chdir(ROOT)
    os.umask(0o022)
    os.environ['RUST_TEST_THREADS'] = '1'
    if args.stage_batch is None:
        from ci_lanes import EXTENDED
        batch = stages.create(ROOT)
        for item in EXTENDED:
            if item.name in stages.SPECS:
                code = stages.stage(ROOT, batch, item.name, item.argv, dict(os.environ) | dict(item.env))
                stages.require(code == 0, 'existing editor stage failed')
    else:
        batch = args.stage_batch.resolve(strict=True)
    output = (args.output or ROOT / 'out/foundry/editor-process' / secrets.token_hex(16)).absolute()
    gate = Gate(ROOT, output, batch)
    gate.unchanged()
    gate.run('D01DefaultBinaryAbsent', ['cargo', 'build', '--locked', '-p', 'artifact_editor', '--bin', 'editor-process'], 101)
    gate.api_absent('D01DefaultParentApiAbsent', 'use desktop_service::editor_dev::HostDesktop;', [], 'desktop_service::editor_dev', 'E0432')
    graph = gate.run('D01ChildGraphExcludesDesktopStore', ['cargo', 'tree', '--locked', '-p', 'artifact_editor', '--no-default-features', '--features', 'host_editor_process_child_v0_dev', '-e', 'normal'])
    graph_names = sorted(set(re.findall(r'([^\s]+) v[0-9][^\s]*', Path(graph['stdout']['path']).read_text())))
    normal, artifact = gate.build('D01ExplicitChildBuild', 'host_editor_process_child_v0_dev', 'editor-process', True)
    artifact['package_names'] = graph_names
    assertion, _ = gate.build('D01ExplicitAssertionChildBuild', 'host_editor_process_child_assertions_v0_dev', 'editor-process', True)
    gate.build('D01ExplicitParentBuild', 'host_editor_process_v0_dev', 'artifact_editor')
    for identity, feature, targets in [
        ('D01StrictNormalChild', 'host_editor_process_child_v0_dev', ['--bin', 'editor-process']),
        ('D01StrictAssertionChild', 'host_editor_process_child_assertions_v0_dev', ['--bin', 'editor-process']),
        ('D01StrictNormalParent', 'host_editor_process_v0_dev', ['--lib', '--test', 'process_task']),
        ('D01StrictAssertionParent', FEATURE, ['--lib', '--test', 'process_task', '--test', 'native_task']),
    ]:
        gate.run(identity, ['cargo', 'clippy', '--locked', '-p', 'artifact_editor',
                            '--no-default-features', '--features', feature, *targets, '--', '-D', 'warnings'])
    os.environ.update(RAMEN_EDITOR_PROCESS_ARTIFACT_PATH=str(normal), RAMEN_EDITOR_PROCESS_ARTIFACT_SHA256=stages.sha(normal),
                      RAMEN_EDITOR_PROCESS_ASSERTION_ARTIFACT_PATH=str(assertion), RAMEN_EDITOR_PROCESS_ASSERTION_ARTIFACT_SHA256=stages.sha(assertion))
    gate.save()
    gate.api_absent('D10ProtectedChromeFdNotExported', 'use desktop_service::editor_dev::HostDesktop; fn probe(h: &HostDesktop) { h.export_process_chrome_fd(); }', ['host_editor_process_v0_dev'], 'export_process_chrome_fd')
    gate.api_absent('D17ChildReceiptSetterApiAbsent', 'use desktop_service::editor_dev::OwnedEditorChild; fn probe(c: &mut OwnedEditorChild) { c.set_receipt(); }', ['host_editor_process_v0_dev'], 'set_receipt')
    gate.api_absent('D17CopiedAllocationCannotMintIntent', 'use desktop_service::editor_dev::NativeSaveIntent; fn probe() { NativeSaveIntent::from_allocation(); }', ['host_editor_process_v0_dev'], 'from_allocation')
    gate.api_absent('D29ForeignNumericPidCannotConstructOwner', 'use desktop_service::editor_dev::OwnedEditorChild; fn probe() { OwnedEditorChild::from_pid(1); }', ['host_editor_process_v0_dev'], 'from_pid')
    for index, source in enumerate(['services/desktop/src/editor_dev/process_editor.rs','services/desktop/src/editor_dev/process_editor/linux.rs','services/desktop/src/editor_dev/process_editor/protocol.rs','services/desktop/src/editor_dev/process_editor/fixtures.rs','services/desktop/src/editor_dev/host/process_bridge.rs']):
        gate.run('D07ActualParentSource'+str(index), ['python3','tools/ci/editor_process_source_policy.py','--source',str(ROOT/source)])
    for identity, function in [('D07ParentEditedDraftSourceReject', 'step_native_editor'), ('D07ParentRasterWithReportedPidSourceReject', 'render_native_editor')]:
        mutant = output / (identity + '.rs')
        mutant.write_text('fn parent() { host.' + function + '(); }\n')
        probe = gate.run(identity, ['python3', 'tools/ci/editor_process_source_policy.py', '--source', str(mutant)], 1)
        probe['artifacts'] = [{**stages.ref(mutant), 'kind': 'source_mutant'}]
    for identity, option in [('D25Scenario32769RecordingCap', '--scenario-boundary-output'), ('D25Aggregate131073RecordingCap', '--boundary-output')]:
        directory = output / identity
        probe = gate.run(identity, ['python3', 'tools/ci/editor_process_recording.py', option, str(directory)])
        probe['artifacts'] = [{**stages.ref(p), 'kind': 'control_leaf'} for p in sorted(directory.glob('controls-*.jsonl'))]
    gate.save()
    # The private app test owns the actual outer subreaper and emits both actual
    # parent-death/drop proofs. Run it before the public D29 consumes its receipt.
    name = 'native::process_assertions::process_d29_actual_parent_death_retains_uncertain_store_quarantine'
    probe = gate.run('D29ActualParentDeathSubreaperQuarantine', ['cargo', 'test', '--locked', '-p', 'artifact_editor', '--features', FEATURE, '--lib', name, '--', '--exact', '--test-threads=1', '--nocapture', '-Z', 'unstable-options', '--format=json'])
    selected(probe, [name])
    gate.save()
    private_names = ['native::process_assertions::' + n for n in rust_cases(ROOT / 'apps/artifact_editor/src/native/process_assertions.rs') if n.startswith('process_')]
    for index, case in enumerate(private_names):
        if case == name:
            continue
        probe = gate.run('PrivateAppBehavior' + str(index), ['cargo', 'test', '--locked', '-p', 'artifact_editor', '--features', FEATURE, '--lib', case, '--', '--exact', '--test-threads=1', '--nocapture'])
        selected(probe, [case])
        gate.save()
    for target in ['editor_allocation_closure', 'editor_unpermitted_commit_closure']:
        closure = gate.run('StoreAuthenticClosure-' + target, ['cargo','test','--locked','-p','store_service','--features','editor_native_save_v0_dev','--test',target,'--','--test-threads=1','--nocapture'])
        selected(closure, rust_cases(ROOT/('services/store_service/tests/' + target + '.rs')))
        gate.save()
    names = ['full_assertions::' + n for n in rust_cases(ROOT / 'apps/artifact_editor/tests/process_support/full_assertions.rs')]
    names += rust_cases(ROOT / 'apps/artifact_editor/tests/process_task.rs')
    helpers = rust_cases(ROOT / 'apps/artifact_editor/tests/process_support/cleanup_owners.rs')
    stages.require(len(helpers) == 3, 'exact source-owned cleanup helper inventory')
    for prefix in ['child_owner::cleanup_owners::tests', 'full_assertions::parent_owners::tests', 'full_assertions::child_group::cleanup_owners::tests', 'full_assertions::app_cases::app_owner::cleanup_owners::tests']:
        names += [prefix + '::' + name for name in helpers]
    # Four preparation-only policy controls intentionally unwind with an
    # unproved fake child and retain a temporary root. Let libtest capture only
    # those controls' expected diagnostics; every actual process consumer keeps
    # uncaptured stderr and must have no INCOMPLETE cleanup marker.
    unwind = 'process_preparation_consuming_unwind_retains_parent_root'
    controls = [name for name in names if name.endswith('::' + unwind)]
    stages.require(len(controls) == 4, 'exact four source-owned consuming-unwind controls')
    public = gate.run('PublicThirtyFamilies', ['cargo', 'test', '--locked', '-p', 'artifact_editor', '--features', FEATURE, '--test', 'process_task', '--', '--test-threads=1', '--nocapture', '--skip', unwind])
    selected(public, [name for name in names if name not in controls])
    policy = gate.run('PublicConsumingUnwindControls', ['cargo', 'test', '--locked', '-p', 'artifact_editor', '--features', FEATURE, '--test', 'process_task', unwind, '--', '--test-threads=1'])
    selected(policy, controls)
    gate.save()
    parent_manifest=output/'parent-io-manifest.json'
    stages.publish(parent_manifest, {'schema_version':1,'run_nonce':gate.nonce,'source_manifest_sha256':gate.source['sha256'],'parent_root':str(output/'parent-io'),'files':stages.tree_rows(output/'parent-io')})
    gate.run('ProcessRecordingReader', ['python3', 'tools/ci/editor_process_reader.py', '--evidence', str(output / 'process-io'), '--nonce', gate.nonce, '--source-sha256', gate.source['sha256'], '--output', str(output / 'recording-reader.json'), '--parent-manifest', str(parent_manifest)])
    stages.require(stages.source_rows(ROOT) == json.loads((output / 'source.json').read_bytes()) and stages.source_links(ROOT) == gate.links and stages.sha(ROOT / 'Cargo.lock') == gate.lock, 'fixed candidate unchanged throughout runtime gate')
    stages.publish(output / 'result.json', {'schema_version': 1, 'status': 'PASS', 'gate': 'editor-process-runtime', 'run_nonce': gate.nonce, 'source_manifest': gate.source, 'gate_record': stages.ref(gate.record)})
    print('EDITOR_PROCESS_RUNTIME: PASS evidence=' + str(output), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
