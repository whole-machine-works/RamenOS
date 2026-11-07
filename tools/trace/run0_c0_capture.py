"""Owned C0 producer and retained report join requiring root runtime registration.

No public fixture issuer, transport callback, replacement address or skip flag
exists. Static preparation is independent of launch permission. Python observer
internals are trusted; the reviewed root guard remains the release boundary.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import threading
import time

import boot_profile_capture as base
import run0_c0_acquire as acquire
import run0_c0_decode as decoder
import run0_c0_entry as entry
import run0_c0_host as host
import run0_c0_wire as transport
import run0_host_cpu_reader as reader
import run0_host_cpu_witness as witness


deny, incomplete = base.deny, base.incomplete
REF_KEYS = ('path', 'sha256', 'length')
RAW_NAMES = {'qmp-in': 'qmp.bin', 'qmp-out': 'qmp-requests.bin',
             'rsp': 'rsp.bin', 'rsp-out': 'rsp-requests.bin', 'serial': 'serial.bin',
             'debug': 'debug.bin', 'qemu_stdout': 'stdout.bin', 'qemu_stderr': 'stderr.bin'}
VM_STREAMS = ('qmp', 'rsp', 'serial', 'debug', 'qemu_stdout', 'qemu_stderr')
PREFIX_STREAMS = ('qmp-in', 'qmp-out', 'rsp', 'rsp-out')


def _fref(value):
    deny(type(value) is dict, 'c0_capture_ref_type')
    checked = decoder._ref(value, 32 << 20)
    return tuple(checked[key] for key in REF_KEYS)


def _ref(value):
    deny(type(value) is tuple and len(value) == 3, 'c0_capture_ref_tuple')
    return decoder._ref(dict(zip(REF_KEYS, value)), 32 << 20)


def _blobs(value):
    store = decoder._Blobs(value)
    incomplete(sum(len(raw) for raw in store.values.values()) <= 256 << 20,
               'c0_capture_input_closure_limit')
    return tuple(sorted(store.values.items()))


def _output_name(name):
    # Immutable prior CAP1 keeps its own flat namespace. These current output
    # names cannot be smuggled into the separately bounded input-pin arrays.
    if name.startswith('prior-cap1/'):
        return False
    return (name.startswith(('prefix-current','operation-','c0-acquired/','metadata-','fields-',
                                 'partial-','pre-wire-'))
            or name in {'report.json','host-report.json','partial-report.json','failure-details.json',
                'control.json','plan.json','observer.json','runtime-observer.json','decode.json',
                'c0-argv.json','vars.fd','c0-stop.bin','registers-before.json','registers-after.json',
                'lifecycle.json','process.json','streams.json','peer.json','peer.bin',
                'sigchld.json','sigchld-spawn.bin','sigchld-open.bin','pre-wire-cleanup.json',
                'hmp-before.txt','hmp-after.txt','layout-before.txt','layout-after.txt',
                *RAW_NAMES.values()})


def _merge(*inventories):
    result = {}
    for inventory in inventories:
        for name, raw in inventory:
            deny(name not in result or result[name] == raw, 'c0_capture_input_identity')
            result[name] = raw
    return result


@dataclass(frozen=True, slots=True, init=False)
class PreparedC0Inputs:
    inputs: str
    run: str
    source_dossier: str
    host_abi: str
    plan_bytes: bytes
    profile_bytes: bytes
    observer_source_bytes: bytes
    abi_ref: tuple
    abi_blobs: tuple
    native_layout: tuple
    field_abi: reader.HostABI
    prior: entry.ValidatedPriorEntry
    prior_blobs: tuple
    prior_admission_ref: tuple
    profile_mapping_ref: tuple
    capability_ref: tuple
    source_persistence_ref: tuple
    pinned_efi: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('use prepare_c0_inputs on exact pinned inputs')

    @property
    def plan(self):
        return witness.strict_json(self.plan_bytes, witness.REPORT_LIMIT)

    @property
    def profile(self):
        return witness.decode_pinned_profile(self.profile_bytes)


@dataclass(frozen=True, slots=True, init=False)
class RegisteredCurrentC0Binding:
    _owner: object
    binding: acquire.CurrentC0RamBinding
    prepared: PreparedC0Inputs
    host_receipt: host.HostObservationReceipt
    layout_receipt: transport.C0LayoutReceipt

    def __init__(self, *args, **kwargs):
        raise TypeError('only the held owned collector registers its current binding')


def _construct(cls, **fields):
    deny(cls in (PreparedC0Inputs, RegisteredCurrentC0Binding,
                 acquire.CurrentC0RamBinding, acquire.AfterC0Binding), 'c0_capture_private_type')
    result = object.__new__(cls)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


def prepare_c0_inputs(inputs, run, source_dossier, host_abi, *, prior_admission_ref,
                      profile_mapping_ref, capability_ref, source_persistence_ref, prior_blobs):
    """Freeze static verified inputs; this function never launches the guest."""
    paths = []
    for value in (inputs, run, source_dossier, host_abi):
        deny(type(value) is Path or type(value) is type(Path()), 'c0_capture_path_type')
        base.safe_path(value)
        deny(value.is_absolute() and value.parent.resolve() == value.parent, 'c0_capture_path')
        paths.append(value)
    inputs, run, source_dossier, host_abi = paths
    prepared = witness.prepare_launch(inputs, run, source_dossier, host_abi)
    plan, profile, profile_raw, _, abi_ref, abi_blobs, layout, abi = prepared
    deny(profile['invocation_profile'] == base.VAPIC_OFF_INVOCATION_PROFILE,
         'c0_capture_exact_profile')
    refs = tuple(_fref(value) for value in (prior_admission_ref, profile_mapping_ref,
                                           capability_ref, source_persistence_ref))
    prior_snapshot = _blobs(prior_blobs)
    for reference in refs:
        deny(not _output_name(reference[0]), 'c0_capture_input_output_collision')
    abi_snapshot = _blobs(abi_blobs)
    store = decoder._Blobs(_merge(abi_snapshot, prior_snapshot))
    profile_ref = witness.CaptureEvidence.ref('profile.json', profile_raw)
    prior = entry.validate_prior_entry(profile_ref, _ref(refs[0]), _ref(refs[1]),
                                      dict(store.values))
    deny(store.get(profile_ref, 65536) == profile_raw and
         prior.invocation_profile == base.VAPIC_OFF_INVOCATION_PROFILE,
         'c0_capture_prior_profile')
    abi_index = witness.strict_json(store.get(abi_ref, witness.REPORT_LIMIT), witness.REPORT_LIMIT)
    decoder._capability_binding({'capability_ref': _ref(refs[2]),
                                 'source_dossier_ref': abi_index['source_dossier_ref']}, store, profile)
    store.get(_ref(refs[3]), witness.REPORT_LIMIT)
    decoder._profile_binding({'profile_ref':profile_ref,'prior_admission_ref':_ref(refs[0]),
                              'profile_mapping_ref':_ref(refs[1])},store)
    prior_snapshot = tuple(sorted((name,store.values[name]) for name in store.verified))
    deny(all(not _output_name(name) for name,_ in prior_snapshot),
         'c0_capture_input_output_collision')
    pinned = witness.read_exact(inputs/'efi', profile['inputs']['efi']['sha256'],
                                profile['inputs']['efi']['length'])
    deny(pinned == store.get(profile['inputs']['efi'], decoder.entry.EFI_LIMIT),
         'c0_capture_efi_identity')
    deny(type(abi) is reader.HostABI, 'c0_capture_host_abi_type')
    witness.validate_native_layout(layout)
    observer = witness.c0_observer_source_bytes()
    deny(type(observer) is bytes and len(observer) <= witness.REPORT_LIMIT,
         'c0_capture_observer_bound')
    manifest = [witness.CaptureEvidence.ref(name, raw) for name, raw in prior_snapshot]
    plan = dict(plan, kind='run0_c0_owned_capture_plan_v0', context='c0',
        observer_ref=witness.CaptureEvidence.ref('observer.json', observer),
        prior_admission_ref=list(refs[0]), profile_mapping_ref=list(refs[1]),
        capability_ref=list(refs[2]), source_persistence_ref=list(refs[3]),
        prior_inputs_sha256=hashlib.sha256(witness.canonical(manifest)).hexdigest())
    return _construct(PreparedC0Inputs, inputs=str(inputs), run=str(run),
        source_dossier=str(source_dossier), host_abi=str(host_abi),
        plan_bytes=witness.canonical(plan), profile_bytes=profile_raw,
        observer_source_bytes=observer, abi_ref=_fref(abi_ref), abi_blobs=abi_snapshot,
        native_layout=tuple(sorted(layout.items())), field_abi=abi, prior=prior,
        prior_blobs=prior_snapshot, prior_admission_ref=refs[0], profile_mapping_ref=refs[1],
        capability_ref=refs[2], source_persistence_ref=refs[3], pinned_efi=pinned)


def _prepared(value, run):
    deny(type(value) is PreparedC0Inputs, 'c0_capture_prepared_type')
    try:
        for name in PreparedC0Inputs.__dataclass_fields__:
            getattr(value, name)
    except AttributeError as error:
        raise base.ProbeError('DENY', 'c0_capture_prepared_fields') from error
    deny(type(run) is type(Path()) and str(run) == value.run, 'c0_capture_run_identity')
    plan = value.plan
    deny(plan['run'] == value.run and plan['inputs'] == value.inputs and
         plan['kind'] == 'run0_c0_owned_capture_plan_v0' and plan['context'] == 'c0',
         'c0_capture_prepared_plan')
    deny(witness.canonical(plan) == value.plan_bytes, 'c0_capture_plan_bytes')
    return plan


class _EvidenceBudget:
    def __init__(self, accounting):
        self.accounting = accounting

    def retain(self, count):
        self.accounting.reserve_output(count, 'output')


class _OwnedC0Runtime:
    """One actual held child, wire, observation and nonrenewable stop."""
    def __init__(self, prepared, owner, wire, accounting, evidence, native, before_spawn,
                 before_spawn_ns):
        deny(type(prepared) is PreparedC0Inputs and type(owner) is witness.OwnedWait and
             type(owner.child) is subprocess.Popen and owner.role == 'qemu' and not owner.reaped,
             'c0_capture_owned_runtime')
        deny(type(wire) is transport.C0Wire, 'c0_capture_wire_type')
        self.prepared, self.owner, self._wire = prepared, owner, wire
        self.accounting, self.evidence, self.native = accounting, evidence, native
        self.before_spawn, self.before_spawn_ns = before_spawn, before_spawn_ns
        self._registered = self._observation = self._host = self._layout = None
        self._session = self._complete = self._snapshot = None
        self._confirmed = None
        self._prefix = self._prefix_ref = None
        self._helper_retained = None
        self._read_claims = {}
        self._closed = False

    def _registration(self):
        plan = _prepared(self.prepared, Path(self.prepared.run))
        witness.require_c0_runtime_registration(self.prepared, plan)
        deny(self.owner.child.returncode is None and not self.owner.reaped and not self._closed
             and self._wire._failure is None, 'c0_capture_owner_not_live')
        return plan

    def _put(self, name, raw, *, purpose='output', charged=False):
        deny(type(raw) is bytes, 'c0_capture_retained_bytes')
        path = self.evidence.run/name
        if name in self.evidence.blobs:
            deny(self.evidence.blobs[name] == raw, 'c0_capture_retained_identity')
            if path.exists():
                return self.evidence.ref(name, raw)
        if not charged:
            self.accounting.reserve_output(len(raw), purpose)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if name in self.evidence.blobs:
            # Explicitly retained copy of an already pinned source input (e.g.
            # profile.json), charged as current output before its actual write.
            witness.write_private(path,raw)
            return self.evidence.ref(name,raw)
        return self.evidence.put(name, raw, charged=True)

    def _json(self, name, value, *, purpose='output'):
        # Size the bounded native record before allocating its retained byte copy.
        encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), allow_nan=False)
        size = 1+sum(len(part.encode('utf-8')) for part in encoder.iterencode(value))
        incomplete(size <= witness.REPORT_LIMIT, 'c0_capture_index_limit')
        if purpose in ('report','failure'):
            self.accounting.redeem_terminal(size,purpose)
        else:
            self.accounting.reserve_output(size, purpose)
        return self._put(name, witness.canonical(value), charged=True)

    def _raw_copy(self, key, name):
        raw = self._wire._raw[key]
        self.accounting.reserve_output(len(raw), 'output')
        return self._put(name, bytes(raw), charged=True)

    def _slice(self, segment, raw_refs):
        if segment is None:
            return None
        deny(type(segment) is transport.WireSlice and segment.stream in raw_refs,
             'c0_capture_wire_slice')
        return witness.slice_ref(raw_refs[segment.stream], segment.offset, segment.length)

    def _retain_op(self, row):
        purpose = self._read_claims.get(row.seq, 'output')
        result = {}
        for key in ('request', 'response'):
            segment = getattr(row, key)
            if segment is None:
                result[key+'_ref'] = None
                continue
            name = f'operation-{row.seq}-{key}.bin'
            if name in self.evidence.blobs:
                result[key+'_ref'] = self.evidence.ref(name, self.evidence.blobs[name])
                continue
            deny(type(segment) is transport.WireSlice and segment.stream in self._wire._raw,
                 'c0_capture_operation_slice')
            self.accounting.reserve_output(segment.length, purpose)
            raw = bytes(memoryview(self._wire._raw[segment.stream])[segment.offset:segment.offset+segment.length])
            deny(len(raw) == segment.length, 'c0_capture_operation_extent')
            result[key+'_ref'] = self._put(name, raw, charged=True)
        return {key: getattr(row, key) for key in ('seq','protocol','operation','started_ns',
                                                  'finished_ns','result')} | result

    def _register_index(self, registers, name):
        return self._json(name, {'schema_version':1,
            'operations':[seq for _, _, seq in registers.values]})

    def _retain_helpers(self):
        if self._helper_retained is not None:
            return self._helper_retained
        observation = self._observation
        incomplete(observation is not None and observation._finished, 'c0_capture_host_incomplete')
        metadata, refs = {}, {}
        for phase in ('before', 'after'):
            helper = observation.helpers['metadata_'+phase]
            # The helper, parsed metadata and separately retained files are distinct
            # representations; the shared budget accounts their physical copies.
            self.accounting.reserve_output(len(helper.output)+len(helper.stderr),'output')
            prepaid={f'metadata-{phase}.bin',f'metadata-{phase}-stderr.bin'}
            def put_helper(name,data):
                return self._put(name,data,charged=name in prepaid)
            refs['metadata_'+phase+'_ref'], metadata[phase] = witness.retain_metadata(
                put_helper, phase, helper.child.pid, helper.lifecycle[0]['started_ns'],
                next(row['finished_ns'] for row in helper.lifecycle if row['operation']=='wait'),
                bytes(helper.output), bytes(helper.stderr))
        helper = observation.helpers['fields']
        deny(bytes(observation.request_sent) == observation.begin_raw+observation.admit_raw,
             'c0_capture_helper_request_identity')
        self.accounting.reserve_output(len(helper.output)+len(helper.stderr)+
            len(observation.begin_raw)+len(observation.admit_raw),'output')
        prepaid={'fields-output.bin','fields-stderr.bin','fields-begin.json','fields-admit.json'}
        def put_fields(name,data):
            return self._put(name,data,charged=name in prepaid)
        refs['reads_ref'], fields = witness.retain_fields(put_fields, helper.child.pid,
            observation.begin_raw, observation.admit_raw, bytes(helper.output),
            bytes(helper.stderr), observation.reads)
        self._helper_retained = refs, metadata, fields
        return self._helper_retained

    def _prefix_current(self):
        raw_refs = {key:self._raw_copy(key, 'prefix-current-'+RAW_NAMES[key])
                    for key in PREFIX_STREAMS}
        self._prefix = raw_refs
        registers = self._wire._before_registers
        register_ref = self._register_index(registers, 'registers-before.json')
        hmp_ref = self._put('hmp-before.txt', self._wire._host_before.hmp_bytes)
        layout_ref = self._put('layout-before.txt', self._layout.raw_bytes)
        event = next(row for row in self._wire.events if row.seq == self._confirmed.stop.stop_event_seq)
        deny(event.protocol == 'rsp', 'c0_capture_stop_event')
        self.accounting.reserve_output(event.wire.length, 'output')
        stop_raw = bytes(memoryview(self._wire._raw[event.wire.stream])[event.wire.offset:event.wire.offset+event.wire.length])
        stop_ref = self._put('c0-stop.bin', stop_raw, charged=True)
        for row in self._wire.operations:
            self._retain_op(row)
        helper_refs, _, _ = self._retain_helpers()
        before, after = dict(self._wire._host_before.operations), dict(self._wire._host_after.operations)
        prefix = {'schema_version':1, 'kind':'run0_c0_current_prefix_v0',
            'run_id':self.prepared.plan['run'].rsplit('/',1)[-1],
            'profile_sha256':self.prepared.prior.probe_profile_sha256,
            'raw_refs':list(raw_refs.values()), 'host_before':before, 'host_after':after,
            'host_refs':helper_refs, 'registers_before_ref':register_ref,
            'hmp_before_ref':hmp_ref, 'layout_before_ref':layout_ref, 'stop_ref':stop_ref,
            'operations':[self._operation(row,raw_refs) for row in self._wire.operations],
            'events':[self._event(row,raw_refs) for row in self._wire.events]}
        self._prefix_ref = self._json('prefix-current.json', prefix)
        return register_ref,hmp_ref,layout_ref,stop_ref,helper_refs['reads_ref']

    def _operation(self, row, raw_refs):
        return {key:getattr(row,key) for key in ('seq','protocol','operation','started_ns',
                                                'finished_ns','result')} | {
            'request':self._slice(row.request,raw_refs), 'response':self._slice(row.response,raw_refs)}

    def _event(self, row, raw_refs):
        return {key:getattr(row,key) for key in ('seq','protocol','name','received_ns')} | {
            'wire':self._slice(row.wire,raw_refs)}

    def _register_rows(self, registers):
        deny(type(registers) is transport.SelectedC0Registers and registers._session is self._wire._session,
             'c0_capture_register_receipt')
        widths = dict(acquire.REGISTER_WIDTHS)
        return tuple((number,widths[number],value,seq) for number,value,seq in registers.values)

    def issue_current_binding(self, host_receipt, layout_before):
        self._registration()
        wire = self._wire
        deny(self._registered is None and self._host is host_receipt is wire._host_receipt
             and self._layout is layout_before is wire._layout_before and
             host._issued_observation(host_receipt, wire, self._observation._lease),
             'c0_capture_current_receipt_identity')
        process = host_receipt.process_identity
        deny(process[0] == self.owner.child.pid and process[1] == os.getpid() and
             process[2] == self._observation.process['starttime_ticks'], 'c0_capture_parent_identity')
        deny(host_receipt.cpu_identity == wire._host_before.cpu_identity == wire._host_after.cpu_identity
             and host_receipt.finished_ns <= wire.operations[layout_before.operation_seq-1].started_ns,
             'c0_capture_current_order')
        reg_ref,hmp_ref,layout_ref,stop_ref,state_ref = self._prefix_current()
        values = dict((n,v) for n,v,_ in wire._before_registers.values)
        state = self._observation.state
        hmp = decoder._hmp(wire._host_before.hmp_bytes, values)
        mode = decoder._mode({'phys_bits':host_receipt.cpu_identity[2],
            'cr0':values[27], 'cr3':values[29], 'cr4':values[30], 'efer':values[32],
            'cpl':hmp['cpl'],'cs64':hmp['cs64'],'a20':hmp['a20'],
            **{key:state[key] for key in ('no_npt','no_svm_guest','no_smm')}})
        before,after = dict(wire._host_before.operations),dict(wire._host_after.operations)
        proof_values = (self._confirmed.stop.breakpoint_seq,self._confirmed.stop.resume_seq,
            self._confirmed.stop.acknowledge_stop_seq,self._confirmed.query_status_seq,
            wire._current_mode.operation_seq,before['status_seq'],after['status_seq'],layout_before.operation_seq)
        sequences = tuple(sorted((*proof_values,*(seq for _,_,seq in wire._before_registers.values))))
        by_seq = {row.seq:row for row in wire.operations}
        def frozen_slice(segment):
            if segment is None:
                return None
            value = self._slice(segment,self._prefix)
            return (_fref(value['blob']),value['offset'],value['length'])
        abi_index = witness.strict_json(dict(self.prepared.abi_blobs)[self.prepared.abi_ref[0]], witness.REPORT_LIMIT)
        ref_values = (stop_ref,reg_ref,hmp_ref,layout_ref,state_ref,_ref(self.prepared.abi_ref),
            abi_index['source_dossier_ref'],_ref(self.prepared.source_persistence_ref),
            self._prefix_ref,self._prefix_ref)
        binding = _construct(acquire.CurrentC0RamBinding, origin='owned_current_c0',
            prior=self.prepared.prior,confirmed_stop=self._confirmed,wire_identity=wire._session,
            transport_identity=wire.transport_identity,admission_epoch=wire.admission_epoch,
            physical_mode=wire._current_mode.value,run_id=Path(self.prepared.run).name,
            profile_ref=self.prepared.prior.profile_ref,
            profile_sha256=self.prepared.prior.probe_profile_sha256,
            invocation_profile=self.prepared.prior.invocation_profile,
            owner_identity=(process[0],process[2],host_receipt.cpu_identity[1]),cpu=0,thread='01',
            pinned_efi_ref=_fref(self.prepared.profile['inputs']['efi']),state=tuple(mode.items()),
            registers=self._register_rows(wire._before_registers),hmp_raw=wire._host_before.hmp_bytes,
            layout_raw=layout_before.raw_bytes,ranges=layout_before.ranges,
            proof_prefix=tuple(zip(acquire.PROOF_NAMES,proof_values)),
            evidence_refs=tuple((name,_fref(ref)) for name,ref in zip(acquire.REF_NAMES,ref_values)),
            raw_operation_slices=tuple((seq,frozen_slice(by_seq[seq].request),
                                       frozen_slice(by_seq[seq].response)) for seq in sequences),
            stop_event_slice=frozen_slice(next(row.wire for row in wire.events
                if row.seq==self._confirmed.stop.stop_event_seq)),
            host_read_sizes=tuple(row['length'] for row in self._observation.reads),
            stop_ns=self._confirmed.stop.received_ns,vm_deadline_ns=wire._deadline,
            stop_deadline_ns=self._confirmed.stop.received_ns+transport.CONTINUE_NS)
        # Reuse the exact acquisition validation before registering any authority.
        acquire._validate_binding(binding,self.prepared.prior,self.prepared.pinned_efi)
        self._registered = _construct(RegisteredCurrentC0Binding,_owner=self,binding=binding,
            prepared=self.prepared,host_receipt=host_receipt,layout_receipt=layout_before)
        return self._registered

    def issue_after_binding(self, after_registers, final_hmp, layout_after):
        wire = self._wire
        self._registration()
        deny(self._registered is not None and self._complete is wire._reads_complete and
             after_registers is wire._after_registers and final_hmp is wire._final_register_view
             and layout_after is wire._layout_after and layout_after._session is wire._session,
             'c0_capture_after_receipt_identity')
        register_ref = self._register_index(after_registers,'registers-after.json')
        hmp_ref = self._put('hmp-after.txt',final_hmp.raw_bytes)
        layout_ref = self._put('layout-after.txt',layout_after.raw_bytes)
        seqs = (*(seq for _,_,seq in after_registers.values),final_hmp.operation_seq,layout_after.operation_seq)
        rows = {row.seq:row for row in wire.operations}
        inventory = []
        for seq in seqs:
            retained = self._retain_op(rows[seq])
            inventory.append((seq,(_fref(retained['request_ref']),0,retained['request_ref']['length']),
                (_fref(retained['response_ref']),0,retained['response_ref']['length'])))
        return _construct(acquire.AfterC0Binding,binding=self._registered.binding,
            state=self._registered.binding.state,registers=self._register_rows(after_registers),
            hmp_raw=final_hmp.raw_bytes,layout_raw=layout_after.raw_bytes,
            hmp_seq=final_hmp.operation_seq,layout_seq=layout_after.operation_seq,
            finished_ns=wire.operations[layout_after.operation_seq-1].finished_ns,
            evidence_refs=(('registers_after',_fref(register_ref)),('hmp_after',_fref(hmp_ref)),
                           ('layout_after',_fref(layout_ref))),raw_operation_slices=tuple(inventory))

    def acquire(self):
        wire = self._wire
        wire.prelaunch()
        wire.prepare_rsp_reset()
        wire.install_entry_breakpoint(self.prepared.prior)
        wire.resume_to_entry()
        self._confirmed = wire.confirm_entry_stop()
        wire.confirm_stopped_physical_mode(self._confirmed)
        registers = wire.read_selected_registers(self._confirmed,'before')
        plan = self.prepared.plan
        fingerprint = tuple(plan['launch_identity'][key] for key in ('device','inode','size'))
        self._observation = host._OwnedC0Observation(self.owner.child,wire,self._confirmed,registers,
            self.native,self.prepared.field_abi,plan['argv'][0],fingerprint)
        self._host = self._observation.observe()
        self._layout = wire.read_current_layout(self._confirmed,'before')
        registered = self.issue_current_binding(self._host,self._layout)
        ledger = self.accounting.make_acquisition_ledger()
        self._session = acquire.AcquisitionSession(self.prepared.prior,self.prepared.pinned_efi,
                                                  registered.binding,ledger)
        wire.bind_acquisition(registered,self._session)
        while True:
            grant = self._session.next_request()
            if type(grant) is acquire.ReadsComplete:
                self._complete = grant
                break
            receipt = wire.read_physical(grant)
            self._read_claims[receipt.operation_seq] = ('read',grant.intent.request_id,receipt.operation_seq)
            self._session.accept(grant,receipt)
        wire.complete_acquisition(self._complete)
        after = wire.read_selected_registers(self._confirmed,'after')
        hmp = wire.read_final_register_view(self._confirmed,after)
        layout = wire.read_current_layout(self._confirmed,'after')
        self._snapshot = self._session.finish(self.issue_after_binding(after,hmp,layout))
        wire.clear_entry_breakpoint(self._confirmed)
        return self._snapshot


def _issued_current_binding(value, wire):
    """Exact collector registration, never a caller assertion or origin shortcut."""
    if not (type(value) is RegisteredCurrentC0Binding and
            type(getattr(value,'_owner',None)) is _OwnedC0Runtime):
        return False
    owner = value._owner
    try:
        owner._registration()
        return (owner._registered is value and owner._wire is wire and
            value.prepared is owner.prepared and value.host_receipt is owner._host is wire._host_receipt
            and value.layout_receipt is owner._layout is wire._layout_before and
            value.binding.confirmed_stop is owner._confirmed is wire._confirmed_stop and
            value.binding.wire_identity is wire._session and
            host._issued_observation(value.host_receipt,wire,owner._observation._lease))
    except (base.ProbeError,AttributeError,OSError):
        return False



def _retain_snapshot(owner):
    snapshot = owner._snapshot
    incomplete(type(snapshot) is acquire.AcquiredC0Snapshot, 'c0_capture_snapshot_incomplete')
    checkpoint = snapshot.export_record()
    receipts = {row.operation_seq:row for row in snapshot.receipts}
    for record in (*checkpoint['tables'],*checkpoint['objects']):
        count = len(record['read_sequences'])//2
        for phase, seqs in (('first',record['read_sequences'][:count]),
                            ('recheck',record['read_sequences'][count:])):
            ref = record[phase+'_ref']
            raw = snapshot.blobs[ref['path']]
            for seq in seqs:
                receipt = receipts[seq]
                owner.accounting.reserve_output(len(receipt.data),owner._read_claims[seq])
            owner._put(ref['path'],raw,charged=True)
    return checkpoint


def _stream_rows(owner, raw_refs):
    wire, observation = owner._wire, owner._observation
    eof = {row.stream:row for row in wire.eofs}
    incomplete(not wire.io_errors and set(eof) == {'qmp-in','rsp','serial','debug','qemu_stdout','qemu_stderr'},
               'c0_capture_vm_stream_eof')
    rows = []
    for name in VM_STREAMS:
        key = 'qmp-in' if name == 'qmp' else name
        rows.append({'name':name,'raw_ref':raw_refs[key],'eof':True,'error':None})
    refs, metadata, fields = owner._retain_helpers()
    for role in witness.WAIT_ROLES[1:]:
        helper = observation.helpers[role]
        incomplete(helper.closed and helper.reaped and helper.returncode == 0 and
                   not helper.io_errors and set(helper.eofs) == {'stdout','stderr'},
                   'c0_capture_helper_stream_eof')
        if role == 'fields':
            stdout,stderr = fields['output_ref'],fields['stderr_ref']
        else:
            phase = role.removeprefix('metadata_')
            stdout,stderr = metadata[phase]['wire_ref'],metadata[phase]['stderr_ref']
        rows.extend(({'name':role+'_stdout','raw_ref':stdout,'eof':True,'error':None},
                     {'name':role+'_stderr','raw_ref':stderr,'eof':True,'error':None}))
    incomplete(len(rows)==12 and len({row['name'] for row in rows})==12,'c0_capture_all_streams')
    return rows


def _retain_host_join(owner, host_report, raw_refs, control_ref, observer_ref, grace):
    """Reuse accepted metadata/field formats; collect actual C0 lifecycle receipts."""
    observation = owner._observation
    helper_refs, metadata, _ = owner._retain_helpers()
    helpers = observation.helpers
    owners = [owner.owner,*(helpers[role] for role in witness.WAIT_ROLES[1:])]
    incomplete(all(item.reaped and item.returncode == 0 and not item.actions for item in owners),
               'c0_capture_actual_waits')
    lifecycle = sorted((row for item in owners for row in item.lifecycle),key=lambda row:row['started_ns'])
    lifecycle_ref = owner._json('lifecycle.json',{'schema_version':1,
        'rows':[row|{'seq':seq} for seq,row in enumerate(lifecycle,1)]})
    process = observation.process|{'schema_version':1,'lifecycle_ref':lifecycle_ref,
        'exe_before_ref':metadata['before']['exe_identity_ref'],
        'exe_after_ref':metadata['after']['exe_identity_ref']}
    process_ref = owner._json('process.json',process)
    abi_index = witness.strict_json(dict(owner.prepared.abi_blobs)[owner.prepared.abi_ref[0]],witness.REPORT_LIMIT)
    native_ref = abi_index['native_abi_ref']
    pid,uid,gid = struct.unpack('<iII',observation.peer_raw)
    peer_ref = owner._json('peer.json',{'schema_version':1,'socket_role':'qmp','socket_path':'qmp.sock',
        'observed_ns':observation.peer_at_ns,'raw_ref':owner._put('peer.bin',observation.peer_raw),
        'pid':pid,'uid':uid,'gid':gid,'abi_ref':native_ref})
    def signal_receipt(role,raw,at):
        handler,flags = witness.decode_sigchld(raw)
        return {'observed_ns':at,'raw_ref':owner._put('sigchld-'+role+'.bin',raw),
            'abi_ref':native_ref,'handler':handler,'flags':flags,'no_cld_wait_mask':2,
            'observer_pid':os.getpid()}
    sigchld_ref = owner._json('sigchld.json',{'schema_version':1,'sole_reaper_pid':os.getpid(),
        'no_concurrent_reaper':True,'policy_ref':observer_ref,
        'before_spawn':signal_receipt('spawn',owner.before_spawn,owner.before_spawn_ns),
        'before_open':signal_receipt('open',observation.sigchld_raw,observation.sigchld_at_ns)})
    streams_ref = owner._json('streams.json',{'schema_version':1,'rows':_stream_rows(owner,raw_refs)})
    host_report.update(helper_refs,observer_ref=observer_ref,control_ref=control_ref,
        process_ref=process_ref,peer_ref=peer_ref,sigchld_ref=sigchld_ref,state=observation.state,
        admission={'status':'ADMIT','reason':'c0_field_subset'},
        termination={'status':'PASS','first_failure':None,'secondary_failures':[],
            'waits':[witness.wait_result(item,grace if item is owner.owner else 'not_attempted')
                     for item in owners],'streams_ref':streams_ref})
    return host_report


def _base_reports(prepared, refs):
    plan,profile = prepared.plan,prepared.profile
    run_id = Path(prepared.run).name
    abi_index = witness.strict_json(dict(prepared.abi_blobs)[prepared.abi_ref[0]],witness.REPORT_LIMIT)
    host_report = {'schema_version':1,'kind':'run0_host_cpu_witness_v0','run_id':run_id,
        'origin':'retained_runtime','claims':dict(witness.FALSE_CLAIMS),'fresh_c0_verified':False,
        'profile_ref':refs['profile'],'observer_ref':refs['observer'],
        'source_ref':abi_index['source_dossier_ref'],'abi_ref':_ref(prepared.abi_ref),
        'plan_ref':refs['plan'],'binding':None,
        **dict.fromkeys(('metadata_before_ref','metadata_after_ref','peer_ref','sigchld_ref',
                         'process_ref','reads_ref','state','control_ref'))}
    report = {'schema_version':1,'kind':'run0_c0_inspection_subset_v0','run_id':run_id,
        'profile_ref':refs['profile'],'observer_ref':refs['observer'],
        'source_dossier_ref':abi_index['source_dossier_ref'],
        'capability_ref':_ref(prepared.capability_ref),
        'prior_admission_ref':_ref(prepared.prior_admission_ref),
        'profile_mapping_ref':_ref(prepared.profile_mapping_ref),'argv_ref':refs['argv'],
        'raw_refs':[],'operations':[],'checkpoint':None,'termination':None,
        'claims':dict(decoder.FALSE_CLAIMS),'fresh_c0_verified':False,'remaining_checkpoints':['C1','C2']}
    return host_report,report


def _complete_c0_record(owner, report, raw_refs, final_vars_ref, observer_ref, checkpoint, grace):
    """Assemble records from retained receipts; this pure step issues no witness."""
    _stream_eof_gate(owner)
    incomplete(owner.owner.reaped and owner.owner.returncode==0 and owner._closed and grace=='exited',
               'c0_capture_actual_waits')
    report.update(observer_ref=observer_ref,checkpoint=checkpoint,
        operations=[owner._retain_op(row) for row in owner._wire.operations],
        raw_refs=[*raw_refs.values(),final_vars_ref,*owner._prefix.values(),owner._prefix_ref],
        termination={'status':'PASS','reason':'owned_c0_complete','reaped':owner.owner.reaped,
            'returncode':owner.owner.returncode,'actions':list(owner.owner.actions),'grace':grace,
            'streams':[{'name':name.removeprefix('qemu_'),'eof':True,'error':None} for name in VM_STREAMS]})
    incomplete(len(report['raw_refs'])<=16,'c0_capture_raw_ref_limit')
    return report


def _assemble_complete(owner, host_report, report, grace):
    """Finish actual evidence first; only then ask the unchanged validators."""
    incomplete(owner.owner.reaped and owner.owner.returncode==0 and grace=='exited'
               and owner._closed,'c0_capture_cleanup_incomplete')
    wire,prepared = owner._wire,owner.prepared
    incomplete(wire.failure is None and owner._snapshot is not None,'c0_capture_first_failure')
    raw_refs = {key:owner._raw_copy(key,RAW_NAMES[key]) for key in RAW_NAMES}
    for key,prefix_ref in owner._prefix.items():
        incomplete(owner.evidence.blobs[raw_refs[key]['path']].startswith(
            owner.evidence.blobs[prefix_ref['path']]),'c0_capture_prefix_changed')
    profile = prepared.profile
    witness.base.validate_profile(profile,Path(prepared.inputs))
    deny(witness.read_exact(Path(prepared.inputs)/'profile.json',prepared.plan['profile_sha256'],65536)
         == prepared.profile_bytes and witness.c0_observer_source_bytes()==prepared.observer_source_bytes,
         'c0_capture_post_source_changed')
    abi_index = witness.strict_json(dict(prepared.abi_blobs)[prepared.abi_ref[0]],witness.REPORT_LIMIT)
    post = {}
    witness.recheck_runtime(Path(prepared.inputs),profile,abi_index,dict(prepared.abi_blobs),
        expected_identity=prepared.plan['launch_identity'],run=Path(prepared.run),receipts=post,
        deadline=owner.owner.deadline)
    final_vars_path = owner.evidence.run/'vars.fd'
    base.private_regular(final_vars_path)
    incomplete(final_vars_path.stat().st_size==profile['inputs']['initial_vars']['length'],
               'c0_capture_vars_length')
    owner.accounting.reserve_output(final_vars_path.stat().st_size,'output')
    with final_vars_path.open('rb') as stream:
        final_vars = stream.read(profile['inputs']['initial_vars']['length']+1)
    incomplete(len(final_vars)==profile['inputs']['initial_vars']['length'],'c0_capture_vars_length')
    final_vars_ref = owner.evidence.ref('vars.fd',final_vars)
    owner.evidence.blobs['vars.fd']=final_vars
    observer_ref = owner._json('runtime-observer.json',{'schema_version':1,
        'kind':'run0_c0_runtime_observer_v0','run_id':report['run_id'],
        'source_manifest_ref':host_report['observer_ref'],'abi_sha256':prepared.abi_ref[1],
        'launch_env':witness.clean_launch_env(Path(prepared.run)),'postcheck':post,
        'vars_initial_sha256':profile['inputs']['initial_vars']['sha256'],'vars_final_ref':final_vars_ref})
    checkpoint = _retain_snapshot(owner)
    binding = {'context':'c0','run_id':report['run_id'],
        'profile_sha256':prepared.prior.probe_profile_sha256,'cpu_index':0,
        'qmp_thread_id':owner._host.cpu_identity[1],'rsp_thread':'01','stop_id':'C0',
        'stop_ref':checkpoint['stop_ref'],'resume_seq':checkpoint['resume_seq'],
        'breakpoint_seq':checkpoint['breakpoint_seq'],
        'control_before_seq':dict(wire._host_before.operations)['status_seq'],
        'control_after_seq':dict(wire._host_after.operations)['status_seq']}
    host_report['binding']=binding
    control = {'schema_version':1,'scope':'shared_c0','run_id':report['run_id'],
        'profile_sha256':prepared.prior.probe_profile_sha256,'clock':'host_monotonic_ns',
        'raw_qmp_in_ref':raw_refs['qmp-in'],'raw_qmp_out_ref':raw_refs['qmp-out'],
        'raw_rsp_in_ref':raw_refs['rsp'],'raw_rsp_out_ref':raw_refs['rsp-out'],
        'operations':[owner._operation(row,raw_refs) for row in wire.operations],
        'events':[owner._event(row,raw_refs) for row in wire.events],
        'before':dict(wire._host_before.operations),'after':dict(wire._host_after.operations)}
    control_ref = owner._json('control.json',control)
    _retain_host_join(owner,host_report,raw_refs,control_ref,observer_ref,grace)
    host_ref = owner._json('host-report.json',host_report,purpose='report')
    _complete_c0_record(owner,report,raw_refs,final_vars_ref,observer_ref,checkpoint,grace)
    report_ref = owner._json('report.json',report,purpose='report')
    # Neither final witness nor final C0 interpretation exists before all cleanup.
    prerequisite = witness.validate_report(host_ref,owner.evidence.blobs)
    decoded = decoder.decode_c0('retained_runtime',report_ref,owner.evidence.blobs,prerequisite)
    incomplete(decoded['status']=='PASS','c0_capture_final_replay_'+decoded['reason'])
    owner._json('decode.json',decoded,purpose='report')
    return report,report_ref


def _cause(error):
    if type(error) is decoder.C0DecodeError:
        error=base.ProbeError(error.status,error.reason)
    return witness.failure_reason(error)


def _failure_record(owner, report, failures, grace):
    first = failures[0]
    report['termination']={'status':first['status'],'reason':first['reason'],
        'reaped':owner.owner.reaped,'returncode':owner.owner.returncode,
        'actions':list(owner.owner.actions),'grace':grace,
        'streams':[{'name':name.removeprefix('qemu_'),'eof':any(row.stream==('qmp-in' if name=='qmp' else name)
                    for row in owner._wire.eofs),
                    'error':next((row.errno for row in owner._wire.io_errors
                         if row.stream==('qmp-in' if name=='qmp' else name)),None)} for name in VM_STREAMS]}
    details={'schema_version':1,'kind':'run0_c0_partial_capture_v0','failures':list(failures),
        'child_spawned':True,'lifecycle':list(owner.owner.lifecycle),
        'secondary_host_failures':[] if owner._observation is None
            else list(owner._observation.secondary_failures)}
    # Preserve actual raw bytes even when a reply, EOF, close or wait is missing.
    retained=[]
    for key in RAW_NAMES:
        if key in owner._wire._raw:
            try:
                retained.append(owner._raw_copy(key,'partial-'+RAW_NAMES[key]))
            except (base.ProbeError,OSError) as error:
                status,reason=_cause(error)
                details['failures'].append({'status':status,'reason':reason})
    observation=owner._observation
    if observation is not None:
        details['process']=dict(observation.process)
        details['helpers']=[]
        for role,helper in observation.helpers.items():
            record={'role':role,'pid':helper.child.pid if helper.child is not None else None,
                'reaped':helper.reaped,'returncode':helper.returncode,'eofs':sorted(helper.eofs),
                'errors':list(helper.io_errors),'lifecycle':list(helper.lifecycle)}
            for channel,buffer in (('stdout',helper.output),('stderr',helper.stderr)):
                try:
                    owner.accounting.reserve_output(len(buffer),'output')
                    reference=owner._put('partial-'+role+'-'+channel+'.bin',bytes(buffer),charged=True)
                    record[channel+'_ref']=reference
                    retained.append(reference)
                except (base.ProbeError,OSError) as error:
                    record[channel+'_ref']=None
                    status,reason=_cause(error)
                    details['failures'].append({'status':status,'reason':reason})
            details['helpers'].append(record)
    report['raw_refs']=retained
    details['operations']=[{key:getattr(row,key) for key in ('seq','protocol','operation','started_ns',
        'finished_ns','result')} for row in owner._wire.operations]
    details['failures']=details['failures'][:16]
    owner._json('failure-details.json',details,purpose='failure')
    return report,owner._json('partial-report.json',report,purpose='report')


def _close_runtime(owner, connections):
    started = time.monotonic_ns()
    errors=[]
    try:
        owner._wire.close()
    except OSError as error:
        errors.append(error.errno)
    for source in connections:
        try:
            source.close()
        except OSError as error:
            errors.append(error.errno)
    owner.owner._receipt('close',started,'error' if errors else 'ok',
                         errno=errors[0] if errors else None)
    owner._closed=True
    incomplete(not errors,'c0_capture_descriptor_close')


def _teardown(owner, connections, failures):
    wire = owner._wire
    grace='not_attempted'
    def failure(error):
        status,reason = _cause(error)
        failures.append({'status':status,'reason':reason})
        # A local quit preflight rejection may precede any wire-owned failure.
        # Revoke before the failure-only drain; preserve an already-latched cause.
        wire._latch_failure(transport.Failure(status,reason))
    with witness.defer_cleanup_interrupt() as interrupted:
        try:
            # A fixed quit is the only channel cleanup operation. The wire owns
            # ambiguity and one-attempt policy, including response-less INCOMPLETE.
            quit_receipt=wire.request_quit()
            drain=wire.drain_after_quit(quit_receipt,deadline_ns=int(owner.owner.io_deadline*1_000_000_000))
            if drain.first_failure is not None:
                raise base.ProbeError(drain.first_failure.status,drain.first_failure.reason)
            incomplete(quit_receipt.operation.result=='ok' and quit_receipt.operation.response is not None,
                       'c0_capture_quit_reply_missing')
            # Six VM EOFs precede the sole actual parent wait. Helper EOFs were
            # already proven by the issued host observation and remain separate.
            _stream_eof_gate(owner)
            result=owner.owner.wait(min(time.monotonic()+0.5,owner.owner.io_deadline))
            grace='exited' if result is not None else 'timeout'
            incomplete(result==0 and owner.owner.reaped,'c0_capture_owned_quit_incomplete')
        except (base.ProbeError,decoder.C0DecodeError,OSError) as error:
            failure(error)
        finally:
            if not owner.owner.reaped:
                # Existing OwnedWait is the sole actual reaper. During forced
                # termination continue draining with its pump before each wait.
                try:
                    owner.owner._signal(signal.SIGTERM,'SIGTERM')
                    _failure_drain(owner)
                    if owner.owner.wait(min(time.monotonic()+0.25,owner.owner.io_deadline),
                                        pump=lambda:_failure_drain(owner)) is None:
                        owner.owner._signal(signal.SIGKILL,'SIGKILL')
                        _failure_drain(owner)
                        owner.owner.wait(owner.owner.deadline,pump=lambda:_failure_drain(owner))
                except (base.ProbeError,OSError) as error:
                    failure(error)
            if not owner.owner.reaped:
                failure(base.ProbeError('INCOMPLETE','c0_capture_owned_wait_uncertain'))
            try:
                _close_runtime(owner,connections)
            except (base.ProbeError,OSError) as error:
                failure(error)
    if interrupted[0]:
        failure(KeyboardInterrupt())
    return grace


def _stream_eof_gate(owner):
    actual={row.stream for row in owner._wire.eofs}
    incomplete(not owner._wire.io_errors and actual=={'qmp-in','rsp','serial','debug','qemu_stdout','qemu_stderr'},
               'c0_capture_vm_stream_eof')
    observation=owner._observation
    incomplete(observation is not None and observation._finished and
        all(helper.reaped and helper.closed and helper.returncode==0 and not helper.io_errors
            and set(helper.eofs)=={'stdout','stderr'} for helper in observation.helpers.values())
        and len(observation.helpers)==3,'c0_capture_helper_stream_eof')


def _failure_drain(owner):
    # The wire author owns this bounded terminal pump as part of quit/drain.
    receipt=getattr(owner._wire,'_quit',None)
    try:
        deadline=min(time.monotonic_ns()+10_000_000,int(owner.owner.deadline*1_000_000_000))
        if receipt is not None:
            owner._wire.drain_after_quit(receipt,deadline_ns=deadline)
        else:
            owner._wire._drain_failed_owner(deadline_ns=deadline)
    except (base.ProbeError,OSError):
        # A prior failed drain remains failed. Continue the owned wait/kill
        # sequence; a late EOF cannot erase or repair the earlier outcome.
        pass


def _cleanup_unbound(owner, connections, accounting):
    """Bounded failed-launch drain; no protocol or successful EOF is invented."""
    records={'raw':{},'eofs':[],'errors':[],'lifecycle':owner.lifecycle}
    selector=selectors.DefaultSelector()
    try:
        for ordinal,source in enumerate(connections):
            if source.closed:
                continue
            os.set_blocking(source.fileno(),False)
            records['raw'][ordinal]=bytearray()
            selector.register(source,selectors.EVENT_READ,ordinal)
        def pump():
            if not selector.get_map() or time.monotonic()>=owner.deadline:
                return
            for key,_ in selector.select(0):
                try:
                    allowance=accounting.available('output')
                    incomplete(allowance>0,'storage_limit')
                    data=os.read(key.fileobj.fileno(),min(65536,allowance))
                except BlockingIOError:
                    continue
                except OSError as error:
                    records['errors'].append({'descriptor':key.data,'errno':error.errno})
                    selector.unregister(key.fileobj)
                    continue
                if data:
                    accounting.reserve_output(len(data),'output')
                    records['raw'][key.data].extend(data)
                else:
                    records['eofs'].append({'descriptor':key.data,'observed_ns':time.monotonic_ns()})
                    selector.unregister(key.fileobj)
        if owner.child is not None and not owner.reaped:
            owner._signal(signal.SIGTERM,'SIGTERM')
            pump()
            if owner.wait(min(time.monotonic()+0.25,owner.io_deadline),pump=pump) is None:
                owner._signal(signal.SIGKILL,'SIGKILL')
                owner.wait(owner.deadline,pump=pump)
        pump()
    finally:
        selector.close()
        stamp=time.monotonic_ns()
        for source in connections:
            try:
                source.close()
            except OSError as error:
                records['errors'].append({'descriptor':None,'errno':error.errno})
        if owner.child is not None:
            owner._receipt('close',stamp,'error' if records['errors'] else 'ok',
                errno=records['errors'][0]['errno'] if records['errors'] else None)
    return records


def _connect_vm_sockets(run, started_ns, connections):
    """Connect the fixed VM roles; the collector retains endpoint ownership."""
    streams={}
    for name,socket_name in (('qmp','qmp.sock'),('rsp','gdb.sock'),
                             ('serial','serial.sock'),('debug','debug.sock')):
        connection=witness.connect_owned(run/socket_name,min(time.monotonic()+base.RESPONSE_SECONDS,
            (started_ns+transport.OWNER_NS-transport.TEARDOWN_NS)/1_000_000_000))
        connections.append(connection)
        streams[name]=connection
    return streams


def run_c0_capture(prepared, run):
    """Run one exact registered owned plan; reject unregistered inputs before launch."""
    plan=_prepared(prepared,run)
    witness.require_c0_runtime_registration(prepared,plan)  # before any Popen or run mutation
    deny(threading.current_thread() is threading.main_thread() and threading.active_count()==1,
         'main_thread_owner_required')
    from run0_c0_budget import C0Accounting
    native=witness.NativeQueries(dict(prepared.native_layout))
    started_ns=time.monotonic_ns()
    accounting=C0Accounting(started_ns)
    base.create_run(run)
    evidence=witness.CaptureEvidence(run,_EvidenceBudget(accounting),
                                    _merge(prepared.abi_blobs,prepared.prior_blobs))
    # This temporary retention surface has no authority or child/wire registration.
    class _PrelaunchRetention:
        pass
    retained=_PrelaunchRetention()
    retained.accounting,retained.evidence=accounting,evidence
    retained._put=_OwnedC0Runtime._put.__get__(retained)
    retained._json=_OwnedC0Runtime._json.__get__(retained)
    refs={'profile':retained._put('profile.json',prepared.profile_bytes),
          'observer':retained._put('observer.json',prepared.observer_source_bytes),
          'plan':retained._put('plan.json',prepared.plan_bytes),
          'argv':retained._json('c0-argv.json',plan['argv'])}
    host_report,report=_base_reports(prepared,refs)
    vars_ref=prepared.profile['inputs']['initial_vars']
    accounting.reserve_output(vars_ref['length'],'output')
    witness.write_private(run/'vars.fd',witness.read_exact(Path(prepared.inputs)/'initial_vars',
        vars_ref['sha256'],vars_ref['length']))
    owner=witness.OwnedWait('qemu',(started_ns+transport.OWNER_NS)/1_000_000_000)
    connections=[]
    runtime=None
    failures=[]
    try:
        abi_index=witness.strict_json(dict(prepared.abi_blobs)[prepared.abi_ref[0]],witness.REPORT_LIMIT)
        witness.recheck_runtime(Path(prepared.inputs),prepared.profile,abi_index,dict(prepared.abi_blobs),
            expected_identity=plan['launch_identity'],run=run,deadline=owner.io_deadline)
        witness.require_c0_runtime_registration(prepared,plan)  # immediately before sole actual spawn
        before_spawn=native.sigchld()
        before_spawn_ns=time.monotonic_ns()
        witness.decode_sigchld(before_spawn)
        with witness.defer_cleanup_interrupt() as interrupted:
            stamp=time.monotonic_ns()
            owner.child=subprocess.Popen(plan['argv'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,start_new_session=True,close_fds=True,umask=0o077,
                env=witness.clean_launch_env(run),bufsize=0)
            owner._receipt('spawn',stamp,'ok')
        if interrupted[0]:
            raise KeyboardInterrupt
        connections.extend((owner.child.stdout,owner.child.stderr))
        streams=_connect_vm_sockets(run,started_ns,connections)
        for name,stream in (('qemu_stdout',owner.child.stdout),('qemu_stderr',owner.child.stderr)):
            os.set_blocking(stream.fileno(),False)
            streams[name]=stream
        wire=transport.C0Wire(streams.pop('qmp'),streams,started_ns=started_ns,accounting=accounting)
        runtime=_OwnedC0Runtime(prepared,owner,wire,accounting,evidence,native,before_spawn,before_spawn_ns)
        runtime.acquire()
    except (base.ProbeError,decoder.C0DecodeError,OSError,KeyboardInterrupt) as error:
        status,reason=_cause(error)
        failures.append({'status':status,'reason':reason})
        if runtime is not None:
            runtime._wire._latch_failure(transport.Failure(status,reason))
    finally:
        if runtime is not None:
            grace=_teardown(runtime,connections,failures)
        else:
            grace='not_attempted'
            # A connection/constructor failure still retains sole-parent cleanup;
            # no fabricated wire EOF or successful close report can result.
            with witness.defer_cleanup_interrupt():
                try:
                    cleanup=_cleanup_unbound(owner,connections,accounting)
                    buffers=cleanup.pop('raw')
                    cleanup['raw_refs']=[]
                    for key,buffer in buffers.items():
                        accounting.reserve_output(len(buffer),'output')
                        cleanup['raw_refs'].append(retained._put('pre-wire-'+str(key)+'.bin',
                            bytes(buffer),charged=True))
                    retained._json('pre-wire-cleanup.json',cleanup,purpose='failure')
                    report['raw_refs']=cleanup['raw_refs']
                except (base.ProbeError,OSError) as error:
                    status,reason=_cause(error)
                    failures.append({'status':status,'reason':reason})
    if runtime is None:
        status=failures[0]['status'] if failures else 'INCOMPLETE'
        reason=failures[0]['reason'] if failures else 'c0_capture_pre_wire_incomplete'
        report['termination']={'status':status,'reason':reason,'reaped':owner.reaped,
            'returncode':owner.returncode,'actions':list(owner.actions),'grace':grace,
            'streams':[{'name':name.removeprefix('qemu_'),'eof':False,'error':None} for name in VM_STREAMS]}
        return report,retained._json('partial-report.json',report,purpose='report')
    if not failures:
        try:
            return _assemble_complete(runtime,host_report,report,grace)
        except (base.ProbeError,decoder.C0DecodeError,OSError,KeyboardInterrupt) as error:
            status,reason=_cause(error)
            failures.append({'status':status,'reason':reason})
    return _failure_record(runtime,report,failures,grace)
