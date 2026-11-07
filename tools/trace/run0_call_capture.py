"""Closed parent inputs and owned capture integration.

Static preparation authenticates inputs, not a running process or guest stop.
Runtime registration deliberately remains INCOMPLETE until the actual parent
producer, its source closure and execution plan have been independently reviewed.
Python observer internals are trusted host tooling, not a security boundary.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import subprocess

import boot_profile_capture as base
import run0_c0_decode as decoder
import run0_c0_entry as entry
import run0_call_decode as pure
from run0_call_read import BlobRef
import run0_host_cpu_reader as reader
import run0_host_cpu_witness as witness

deny, incomplete = base.deny, base.incomplete
REF_KEYS = ('path', 'sha256', 'length')
INPUT_BYTES = 256 << 20
CALLER_MANIFEST_SHA256 = 'fa31830fa2607c355fae3fa3b1146b376bbb1ac700c0382dffcdfce3a639b16b'
PLAN_INPUT_FIELDS = ('prior_admission_ref', 'profile_mapping_ref', 'capability_ref',
                     'source_persistence_ref', 'caller_manifest_ref')
PARENT_SOURCE_NAMES = witness.C0_OBSERVER_SOURCE_NAMES + (
    'run0_call_owner.py', 'run0_call_read.py', 'run0_call_budget.py',
    'run0_call_decode.py', 'run0_call_session.py', 'run0_call_wire.py',
    'run0_call_host.py', 'run0_call_capture.py',
)
RAW_NAMES = ('qmp.bin', 'qmp-requests.bin', 'rsp.bin', 'rsp-requests.bin',
             'serial.bin', 'debug.bin', 'stdout.bin', 'stderr.bin')


def _ref(value):
    return decoder._ref(value, 32 << 20)


def _fref(value):
    checked = _ref(value)
    return tuple(checked[key] for key in REF_KEYS)


def _output_name(name):
    deny(type(name) is str, 'call_capture_output_name')
    if name.startswith(('prior-cap1/', 'prior-caller/')):
        return False
    # profile.json is the one shared input/output role: its exact prepared bytes
    # are verified below. Other current-output names cannot arrive as prior data.
    return (name.startswith(('raw/', 'epochs/', 'operations/', 'memory/', 'transitions/',
                             'metadata-', 'fields-', 'pre-wire-'))
            or name in {*RAW_NAMES, 'parent.json', 'report.json', 'host-report.json',
                'partial-report.json', 'failure-details.json', 'control.json',
                'plan.json', 'observer.json', 'runtime-observer.json', 'decode.json',
                'call-argv.json', 'vars.fd', 'lifecycle.json', 'process.json',
                'streams.json', 'peer.json', 'peer.bin', 'sigchld.json',
                'sigchld-spawn.bin', 'sigchld-open.bin', 'pre-wire-cleanup.json',
                'argv.json', 'input-closure.json', 'caller-manifest.json',
                'source-persistence.json', 'source-closure.json', 'source-postcheck.json',
                'raw-inventory.json', 'map-facts.json',
                'selected-call.json', 'map-extent.json', 'map-index.json',
                'coverage.json', 'map-translation-plan.json'})


def _snapshot_blobs(values):
    deny(type(values) is dict and len(values) <= 4096, 'call_capture_blob_mapping')
    total = 0
    for name, data in values.items():
        deny(type(name) is str and type(data) is bytes, 'call_capture_blob_contents')
        total += len(data)
        incomplete(total <= INPUT_BYTES, 'call_capture_input_closure_limit')
    # Size/type bounds precede the private lookup and sorted tuple allocations.
    decoder._Blobs(values)
    return tuple(sorted(values.items()))


def _merge(*inventories):
    result = {}
    total = 0
    for inventory in inventories:
        deny(type(inventory) is tuple and len(inventory) <= 4096,
             'call_capture_input_inventory')
        for row in inventory:
            deny(type(row) is tuple and len(row) == 2 and type(row[0]) is str
                 and type(row[1]) is bytes, 'call_capture_input_row')
            name, raw = row
            if name in result:
                deny(result[name] == raw, 'call_capture_input_identity')
            else:
                incomplete(len(result) < 4096 and total + len(raw) <= INPUT_BYTES,
                           'call_capture_input_closure_limit')
                total += len(raw)
                result[name] = raw
    return result


def _bind_caller(reference, store, efi, symbols):
    """Consume the accepted static derivation; never rediscover a caller/site."""
    reference = _ref(reference)
    deny(reference['sha256'] == CALLER_MANIFEST_SHA256,
         'call_capture_caller_manifest_pin')
    manifest = witness.strict_json(store.get(reference, witness.REPORT_LIMIT),
                                   witness.REPORT_LIMIT)
    deny(type(efi) is bytes and type(symbols) is bytes
         and hashlib.sha256(efi).hexdigest() == pure.EFI_HASH
         and hashlib.sha256(symbols).hexdigest() == pure.PDB_HASH,
         'call_capture_caller_executable_identity')
    deny(manifest.get('efi_sha256') == pure.EFI_HASH
         and manifest.get('pdb_sha256') == pure.PDB_HASH
         and manifest.get('pdb_guid') == pure.GUID
         and type(manifest.get('pdb_age')) is int and manifest['pdb_age'] == 1,
         'call_capture_caller_manifest_identity')
    rows = manifest.get('artifacts')
    deny(type(rows) is list and 1 <= len(rows) <= 64, 'call_capture_caller_artifacts')
    prefix = reference['path'].rsplit('/', 1)[0] + '/' if '/' in reference['path'] else ''
    names = set()
    code = {}
    for row in rows:
        checked = _ref(row)
        deny('/' not in checked['path'] and checked['path'] not in names,
             'call_capture_caller_artifact_path')
        names.add(checked['path'])
        data = store.get(dict(checked, path=prefix + checked['path']), 32 << 20)
        if checked['path'] in ('caller-code.bin', 'guest-helper-code.bin'):
            code[checked['path']] = data
    deny(set(code) == {'caller-code.bin', 'guest-helper-code.bin'},
         'call_capture_caller_code_missing')
    caller, helper = manifest['caller'], manifest['guest_helper']
    expected_caller = {'rva_start':0x6200, 'rva_end_exclusive':0x63b3, 'length':435,
        'file_offset':22016, 'call_rva':0x634d, 'return_rva':0x6350,
        'code_sha256':pure.CALLER_HASH}
    expected_helper = {'rva_start':0x1810, 'rva_end_exclusive':0x196c, 'length':348,
        'scratch_rva':0x7f998, 'scratch_source_size':32768}
    deny(type(caller) is dict and type(helper) is dict
         and all(pure._same_json(caller.get(k), v) for k,v in expected_caller.items())
         and all(pure._same_json(helper.get(k), v) for k,v in expected_helper.items()),
         'call_capture_caller_recipe')
    # The immutable accepted EFI and derivation pin fix these exact file spans.
    # These comparisons do not turn a preferred base or RVA into a live address.
    deny(efi[22016:22451] == code['caller-code.bin']
         and efi[0xc10:0xd6c] == code['guest-helper-code.bin'],
         'call_capture_caller_loaded_source')
    pinned = pure.PinnedCaller(BlobRef(**reference), pure.EFI_HASH, pure.PDB_HASH,
        pure.GUID, 1, code['caller-code.bin'], code['guest-helper-code.bin'])
    pure._pinned(pinned)
    return pinned


def parent_observer_source_bytes():
    """Exact closed transitive source names; absence is not a release waiver."""
    directory = Path(base.__file__).resolve().parent
    initial = witness.strict_json(witness.observer_source_bytes(), 65536)
    sources = []
    for name in PARENT_SOURCE_NAMES:
        try:
            data, _ = witness._read_regular(directory/name, 1 << 20, private=False)
        except FileNotFoundError as error:
            raise base.ProbeError('INCOMPLETE', 'call_capture_source_missing') from error
        sources.append({'path':name, 'length':len(data),
                        'sha256':hashlib.sha256(data).hexdigest()})
    deny(len(set(PARENT_SOURCE_NAMES)) == len(PARENT_SOURCE_NAMES),
         'call_capture_source_inventory')
    return witness.canonical(dict(schema_version=1, kind='run0_call_observer_v0',
                                  python=initial['python'], sources=sources))


@dataclass(frozen=True, slots=True, init=False)
class PreparedCallInputs:
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
    caller_manifest_ref: tuple
    pinned_efi: bytes
    pinned_caller: pure.PinnedCaller

    def __init__(self, *args, **kwargs):
        raise TypeError('use prepare_call_inputs on the exact immutable inputs')

    @property
    def plan(self):
        return witness.strict_json(self.plan_bytes, witness.REPORT_LIMIT)

    @property
    def profile(self):
        return witness.decode_pinned_profile(self.profile_bytes)


@dataclass(frozen=True, slots=True, init=False)
class ClosedOwnedCallRegistration:
    _owner: object
    prepared: PreparedCallInputs
    qemu_owner: object
    wire: object
    deadlines: object
    accounting: object
    inventory: object
    parent_identity: object
    transition_owner: object
    read_attempts: dict
    read_operations: dict

    def __init__(self, *args, **kwargs):
        raise TypeError('only the genuine owned parent publishes registration')


@dataclass(frozen=True, slots=True, init=False)
class RegisteredCurrentEpochBinding:
    _owner: object
    registration: ClosedOwnedCallRegistration
    binding: object
    session: object
    retainer: object
    host_receipt: object
    layout_receipt: object

    def __init__(self, *args, **kwargs):
        raise TypeError('only the held parent publishes a complete current epoch')


@dataclass(frozen=True, slots=True, init=False)
class BoundCallTarget:
    _owner: object
    registration: ClosedOwnedCallRegistration
    closed: object
    source_fact: object
    source_epoch: str
    target_epoch: str
    address: int

    def __init__(self, *args, **kwargs):
        raise TypeError('a copied fact or numeric address is not a target receipt')


class _OwnedCallRuntime:
    """Reserved exact owner shape; no constructor currently publishes a graph."""
    __slots__ = ('prepared', '_registration', 'qemu_owner', '_wire', 'deadlines',
        'accounting', 'inventory', 'parent_identity', 'transition_owner',
        'read_attempts', 'read_operations', 'native', 'before_spawn',
        'before_spawn_ns', '_descriptors', '_children', '_current', '_closed_epochs',
        '_fact_receipts', '_failure', '_closed')

    def __init__(self, *args, **kwargs):
        raise TypeError('the genuine parent graph producer is not yet registered')


def _construct_prepared(**fields):
    deny(set(fields) == set(PreparedCallInputs.__dataclass_fields__),
         'call_capture_prepared_fields')
    result = object.__new__(PreparedCallInputs)
    for name, value in fields.items():
        object.__setattr__(result, name, value)
    return result


def prepare_call_inputs(inputs, run, source_dossier, host_abi, *, prior_admission_ref,
                        profile_mapping_ref, capability_ref, source_persistence_ref,
                        caller_manifest_ref, prior_blobs):
    """Validate/freeze static inputs without outputs, child launch or authority."""
    for path in (inputs, run, source_dossier, host_abi):
        deny(type(path) is type(Path()), 'call_capture_path_type')
        base.safe_path(path)
        deny(path.is_absolute() and path.parent.resolve() == path.parent,
             'call_capture_path')
    original = _snapshot_blobs(prior_blobs)
    values = (prior_admission_ref, profile_mapping_ref, capability_ref,
              source_persistence_ref, caller_manifest_ref)
    refs = tuple(_fref(value) for value in values)
    deny(all(not _output_name(ref[0]) for ref in refs),
         'call_capture_input_output_collision')
    prepared = witness.prepare_launch(inputs, run, source_dossier, host_abi)
    plan, profile, profile_raw, _, abi_ref, abi_blobs, layout, abi = prepared
    deny(profile['invocation_profile'] == base.VAPIC_OFF_INVOCATION_PROFILE,
         'call_capture_exact_profile')
    abi_snapshot = _snapshot_blobs(abi_blobs)
    store = decoder._Blobs(_merge(abi_snapshot, original))
    profile_ref = witness.CaptureEvidence.ref('profile.json', profile_raw)
    references = dict(zip(PLAN_INPUT_FIELDS, (dict(zip(REF_KEYS,r)) for r in refs)))
    prior = entry.validate_prior_entry(profile_ref, references['prior_admission_ref'],
                                      references['profile_mapping_ref'], dict(store.values))
    index = witness.strict_json(store.get(abi_ref, witness.REPORT_LIMIT), witness.REPORT_LIMIT)
    decoder._profile_binding(dict(profile_ref=profile_ref, **references), store)
    decoder._capability_binding(dict(source_dossier_ref=index['source_dossier_ref'],
                                     **references), store, profile)
    deny(references['source_persistence_ref']['sha256'] == witness.C0_SOURCE_PERSISTENCE_SHA256,
         'call_capture_source_persistence_pin')
    store.get(references['source_persistence_ref'], witness.REPORT_LIMIT)
    efi = witness.read_exact(inputs/'efi', profile['inputs']['efi']['sha256'],
                              profile['inputs']['efi']['length'])
    deny(efi == store.get(profile['inputs']['efi'], base.INPUT_LIMITS['efi']),
         'call_capture_efi_identity')
    symbols_ref = profile['inputs']['symbols']
    symbols = witness.read_exact(inputs/'symbols', symbols_ref['sha256'], symbols_ref['length'])
    pinned = _bind_caller(references['caller_manifest_ref'], store, efi, symbols)
    # The symbols are launch inputs already checked by prepare_launch. Retain an
    # explicit verified source reference in the same immutable input inventory.
    deny(symbols_ref['path'] not in store.values or store.values[symbols_ref['path']] == symbols,
         'call_capture_symbols_identity')
    merged = _merge(tuple(sorted(store.verified.items())), ((symbols_ref['path'], symbols),))
    frozen = _snapshot_blobs(merged)
    deny(all(not _output_name(name) for name,_ in frozen),
         'call_capture_input_output_collision')
    deny(type(abi) is reader.HostABI, 'call_capture_host_abi_type')
    witness.validate_native_layout(layout)
    observer = parent_observer_source_bytes()
    manifest = [witness.CaptureEvidence.ref(name, raw) for name, raw in frozen]
    plan = dict(plan, kind='run0_call_owned_capture_plan_v0', context='call',
        observer_ref=witness.CaptureEvidence.ref('observer.json', observer),
        prior_inputs_sha256=hashlib.sha256(witness.canonical(manifest)).hexdigest(),
        **{name:list(ref) for name,ref in zip(PLAN_INPUT_FIELDS,refs)})
    return _construct_prepared(inputs=str(inputs), run=str(run), source_dossier=str(source_dossier),
        host_abi=str(host_abi), plan_bytes=witness.canonical(plan), profile_bytes=profile_raw,
        observer_source_bytes=observer, abi_ref=_fref(abi_ref), abi_blobs=abi_snapshot,
        native_layout=tuple(sorted(layout.items())), field_abi=abi, prior=prior,
        prior_blobs=frozen, pinned_efi=efi, pinned_caller=pinned,
        **dict(zip(PLAN_INPUT_FIELDS,refs)))


def require_call_runtime_registration(prepared, plan):
    """No prepared value can release the unfinished actual runtime producer."""
    deny(type(prepared) is PreparedCallInputs, 'call_capture_prepared_type')
    try:
        for name in PreparedCallInputs.__dataclass_fields__:
            getattr(prepared, name)
    except AttributeError as error:
        raise base.ProbeError('DENY', 'call_capture_prepared_fields') from error
    raise base.ProbeError('INCOMPLETE', 'call_capture_runtime_producer_unregistered')


def _issued_call_registration(registration, wire):
    # Genuine graph publication and its source guard remain receiving work.
    # A string, caller dictionary, or manually populated slots cannot replace it.
    return False


def run_call_capture(prepared, run):
    """Fail before any run mutation or child until the complete producer exists."""
    require_call_runtime_registration(prepared, {})
    raise base.ProbeError('INCOMPLETE', 'call_capture_runtime_producer_unregistered')
