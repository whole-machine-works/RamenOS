"""Sixteen portable synthetic C0D controls; never a runtime C0 witness."""

import copy
from contextlib import ExitStack
import hashlib
import json
import struct
import tempfile
from pathlib import Path
from types import MappingProxyType
import unittest
from unittest.mock import patch
import zlib

import boot_profile_capture as capture
from test_boot_profile_inputs import pe_fixture, put

try:
    import run0_c0_decode as d
except ModuleNotFoundError as error:
    if error.name != "run0_c0_decode":
        raise
    d = None


U64 = (1 << 64) - 1


def mode(**changes):
    return {"phys_bits": 40, "cr0": (1 << 31) | (1 << 16) | 1,
            "cr3": 0x1000, "cr4": 1 << 5, "efer": (1 << 8) | (1 << 10) | (1 << 11),
            "cpl": 0, "cs64": True, "a20": 1, "no_npt": True,
            "no_svm_guest": True, "no_smm": True, **changes}


def frame(entries):
    data = bytearray(4096)
    for index, value in entries.items():
        struct.pack_into("<Q", data, index * 8, value)
    return bytes(data)


def tables(large=False, root_index=0):
    return {0x1000: frame({root_index: 0x2007}), 0x2000: frame({0: 0x3007}),
            0x3000: frame({0: 0x200087 if large else 0x4007}),
            **({} if large else {0x4000: frame({0: 0x8007, 1: 0x9007})})}


def changed(source, physical, index, value):
    result = dict(source)
    raw = bytearray(result[physical])
    struct.pack_into("<Q", raw, index * 8, value)
    result[physical] = bytes(raw)
    return result


def blob(blobs, name, data):
    blobs[name] = data
    return {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def json_blob(blobs, name, value):
    return blob(blobs, name, json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def efi(kind, pointer):
    size, signature, offset = ((120, 0x5453595320494249, 96) if kind == "system"
                                else (376, 0x56524553544F4F42, 56))
    data = bytearray(size)
    struct.pack_into("<QIIII", data, 0, signature, 0x20046, size, 0, 0)
    struct.pack_into("<Q", data, offset, pointer)
    struct.pack_into("<I", data, 16, zlib.crc32(data))
    return bytes(data)


def crc32c(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value ^ 0xffffffff


def rsp_fixture(memory_reads=None, register_values=None, repeated_setup=False, same_stop_mode=True):
    """Independent ACK-mode transcript with a real indexed async-stop ACK."""
    incoming, outgoing, operations, events, blobs = bytearray(), bytearray(), [], [], {}
    stamp = 100

    def packet(payload):
        encoded = bytearray()
        for value in payload:
            encoded.extend((125, value ^ 32) if value in b"#$}*" else (value,))
        return b"$" + encoded + b"#" + f"{sum(encoded) & 255:02x}".encode()

    def segment(buffer, value):
        row = {"blob": None, "offset": len(buffer), "length": len(value)}
        buffer.extend(value)
        return row

    def operation(name, request, response):
        nonlocal stamp
        req = segment(outgoing, packet(request))
        incoming.extend(b"+")
        reply = segment(incoming, packet(response))
        outgoing.extend(b"+")
        operations.append({"seq": len(operations)+1, "protocol": "rsp", "operation": name,
            "request": req, "response": reply, "started_ns": stamp,
            "finished_ns": stamp+10, "result": "ok"})
        stamp += 100

    from test_run0_rsp import CORE_XML, TARGET_XML
    operation("supported", b"qSupported:qXfer:features:read+", b"PacketSize=1000;qXfer:features:read+")
    for name, request, reply in (("thread_first", b"qfThreadInfo", b"m01"),
        ("thread_next", b"qsThreadInfo", b"l"), ("thread_current", b"qC", b"QC01"),
        ("thread_general", b"Hg01", b"OK"), ("thread_continue", b"Hc01", b"OK")):
        operation(name, request, reply)
    for label, annex, raw in (("feature_target", b"target.xml", TARGET_XML),
                             ("feature_core", b"i386-64bit.xml", CORE_XML)):
        for offset in range(0, len(raw), 1024):
            part = raw[offset:offset+1024]
            marker = b"l" if offset+len(part) == len(raw) else b"m"
            operation(label, b"qXfer:features:read:"+annex+b":"+f"{offset:x},400".encode(), marker+part)
    operation("qemu_supported", b"qqemu.Supported", b"PhyMemMode")
    if repeated_setup:
        operation("supported", b"qSupported:qXfer:features:read+", b"PacketSize=1000;qXfer:features:read+")
    operation("physical_mode_query", b"qqemu.PhyMemMode", b"0")
    operation("physical_mode_enable", b"Qqemu.PhyMemMode:1", b"OK")
    operation("physical_mode_query", b"qqemu.PhyMemMode", b"1")
    candidate = 0x100000 if register_values is None else register_values[16]
    operation("hardware_breakpoint_set", f"Z1,{candidate:x},1".encode(), b"OK")
    req = segment(outgoing, packet(b"c")); reply = segment(incoming, b"+")
    operations.append({"seq": len(operations)+1, "protocol": "rsp", "operation": "resume",
        "request": req, "response": reply, "started_ns": stamp,
        "finished_ns": stamp+10, "result": "ok"})
    stop = segment(incoming, packet(b"T05thread:01;"))
    events.append({"seq": 1, "protocol": "rsp", "received_ns": stamp+20,
                   "wire": stop, "name": "T05thread:01;"})
    ack = segment(outgoing, b"+")
    operations.append({"seq": len(operations)+1, "protocol": "rsp",
        "operation": "acknowledge_stop", "request": ack, "response": None,
        "started_ns": stamp+30, "finished_ns": stamp+40, "result": "ok"})
    stamp += 100
    if same_stop_mode:
        operation("physical_mode_query", b"qqemu.PhyMemMode", b"1")
    values = {number: 0 for number in (*range(24), *range(27, 31), 32)}
    values.update({2: 0x42, 3: 0x120000, 16: 0x100000, 17: 0x202,
                   27: 0x80010001, 29: 0x1000, 30: 0x20, 32: 0xd00})
    if register_values is not None:
        values.update(register_values)
    for pass_number in range(2):
        for number, value in values.items():
            width = 4 if 17 <= number <= 23 else 8
            operation("register_read", f"p{number:x}".encode(),
                      value.to_bytes(width, "little").hex().encode())
        if pass_number == 0:
            for address, data in ([(0x1000, b"\x01")] if memory_reads is None else memory_reads):
                operation("physical_read", f"m{address:x},{len(data):x}".encode(), data.hex().encode())
    operation("hardware_breakpoint_clear", f"z1,{candidate:x},1".encode(), b"OK")
    in_ref = blob(blobs, "rsp-in.bin", bytes(incoming))
    out_ref = blob(blobs, "rsp-out.bin", bytes(outgoing))
    for row in operations:
        row["request"]["blob"] = out_ref
        if row["response"] is not None:
            row["response"]["blob"] = in_ref
    events[0]["wire"]["blob"] = in_ref
    return {"raw_rsp_in_ref": in_ref, "raw_rsp_out_ref": out_ref,
            "operations": operations, "events": events}, blobs


def snapshot_fixture(pml4_entry=0x2007):
    """Independent exact PE/EFI bytes in one 2MiB identity leaf, all reread."""
    pinned = bytes(pe_fixture()); base = 0x200000; rip = base+0x1020
    optional = bytearray(pinned[0x98:0x188]); struct.pack_into("<Q", optional, 24, base)
    code = bytearray(pinned[0x420:0x440]); struct.pack_into("<Q", code, 8, base+0x1234)
    objects = [("pe_header", base, pinned[:64]), ("pe_header", base+0x80, pinned[0x80:0x98]),
        ("pe_header", base+0x98, bytes(optional)), ("pe_header", base+0x188, pinned[0x188:0x1d8]),
        ("entry_code", rip, bytes(code)), ("system_table", 0x210000, efi("system", 0x211000)),
        ("boot_services", 0x211000, efi("boot", 0x212003)),
        ("get_memory_map_code", 0x212003, bytes(range(32)))]
    frames = [(0x1000, 4, frame({0: pml4_entry})), (0x2000, 3, frame({0: 0x3007})),
              (0x3000, 2, frame({1: 0x200087}))]
    requests = [(address+offset, data[offset:offset+2048]) for address, _, data in frames
                for offset in (0, 2048)] + [(address, data) for _, address, data in objects]
    index, blobs = rsp_fixture(requests*2, {16: rip, 3: 0x210000})
    reads = [row["seq"] for row in index["operations"] if row["operation"] == "physical_read"]
    half = len(requests)
    tables_rows = [{"physical": address, "level": level,
        "first_ref": blob(blobs, f"frame-{address:x}-first.bin", data),
        "recheck_ref": blob(blobs, f"frame-{address:x}-again.bin", data),
        "read_sequences": reads[2*i:2*i+2]+reads[half+2*i:half+2*i+2]}
        for i, (address, level, data) in enumerate(frames)]
    object_rows = [{"role": role, "virtual": address, "length": len(data),
        "first_ref": blob(blobs, f"object-{i}-first.bin", data),
        "recheck_ref": blob(blobs, f"object-{i}-again.bin", data),
        "read_sequences": [reads[6+i], reads[half+6+i]]}
        for i, (role, address, data) in enumerate(objects)]
    path = [{"frame": 0x1000, "index": 0, "entry": 0x2007},
            {"frame": 0x2000, "index": 0, "entry": 0x3007},
            {"frame": 0x3000, "index": 1, "entry": 0x200087}]
    snapshot = {"id": "C0", "phase": "firmware_active", "rip": rip, "loaded_base": base,
        "image_handle": 0x42, "system_table": 0x210000, "boot_services": 0x211000,
        "get_memory_map": 0x212003, "stop_ref": None, "resume_seq": 5, "breakpoint_seq": 4,
        "registers_before_ref": None, "registers_after_ref": None,
        "hmp_before_ref": None, "hmp_after_ref": None,
        "layout_before_ref": None, "layout_after_ref": None,
        "tables": tables_rows, "objects": object_rows,
        "translations": [{"virtual": address, "physical": address, "length": len(data),
            "path": copy.deepcopy(path), "writable": True, "executable": True, "user": True,
            "page_bytes": 1 << 21} for _, address, data in objects],
        "observed_consistent": True, "atomic_snapshot": False, "device_quiescence_verified": False,
        "call_ref": None}
    return snapshot, blobs, index, pinned, {"loaded_base": base, "entry_address": rip}


def synthetic_c0_hmp(values):
    names = ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
             "R8 ", "R9 ", "R10", "R11", "R12", "R13", "R14", "R15")
    lines = ["", "CPU#0"]
    for first in range(0, 16, 4):
        lines.append(" ".join(f"{names[i]}={values[i]:016x}" for i in range(first, first+4)))
    lines.append(f"RIP={values[16]:016x} RFL={values[17]:08x} [-------] CPL=0 II=0 A20=1 SMM=0 HLT=0")
    for name, number in (("ES", 21), ("CS", 18), ("SS", 19), ("DS", 20), ("FS", 22), ("GS", 23)):
        flags = 0x209b00 if name == "CS" else 0x009300
        lines.append(f"{name} ={values[number]:04x} 0000000000000000 0000ffff {flags:08x}")
    lines.extend(["GDT=     0000000000005000 00000030", "IDT=     0000000000006000 00000fff",
        f"CR0={values[27]:08x} CR2={values[28]:016x} CR3={values[29]:016x} CR4={values[30]:08x}",
        f"EFER={values[32]:016x}"])
    return "\r\n".join(lines)+"\r\n"


def full_fixture(folder, invocation_profile=capture.INVOCATION_PROFILE, *, current_layouts=None):
    import boot_profile_inputs as entry
    import run0_host_cpu_witness as witness
    import run0_rsp_capability as cap
    from test_run0_host_cpu_witness import synthetic_host_report, reader_controls

    snapshot, blobs, rsp_index, pinned, candidate = snapshot_fixture()
    inputs = {}
    for name in capture.INPUT_LIMITS:
        data = pinned if name == "efi" else (reader_controls.elf_fixture() if name == "qemu"
                                             else b"synthetic input "+name.encode())
        inputs[name] = blob(blobs, "7z.so" if name == "seven_zip_module" else name, data)
    profile = {"schema_version": 1, "kind": "boot_profile_probe_inputs_v0",
        "invocation_profile": invocation_profile, "source_commit": "1"*40,
        "assembled_patch_sha256": hashlib.sha256(b"").hexdigest(), "diagnostic_image_name": "fixture.efi",
        "inputs": inputs, "provenance": {name: blob(blobs, "provenance/"+name, b"synthetic "+name.encode())
                                       for name in capture.PROVENANCE_KEYS}}
    remap = {}
    host, blobs, put_blob = synthetic_host_report(folder, rsp_index=rsp_index, rsp_blobs=blobs,
                                                 profile=profile, sequence_map=remap,
                                                 qmp_layouts=current_layouts)
    control = json.loads(blobs[host["control_ref"]["path"]])
    replay = d.validate_c0_rsp(control, blobs)
    for row in snapshot["tables"]+snapshot["objects"]:
        row["read_sequences"] = [remap[seq] for seq in row["read_sequences"]]
    snapshot.update(stop_ref=host["binding"]["stop_ref"], resume_seq=replay["resume_seq"],
                    breakpoint_seq=replay["breakpoint_seq"])
    for phase in ("before", "after"):
        snapshot["registers_"+phase+"_ref"] = put_blob("registers-"+phase+".json",
            {"schema_version": 1, "operations": list(replay[phase+"_sequences"])})

    def slice_bytes(ref):
        raw = blobs[ref["blob"]["path"]]
        return raw[ref["offset"]:ref["offset"]+ref["length"]]

    hmps = [row for row in control["operations"] if row["operation"] == "hmp_registers"]
    layouts = [row for row in control["operations"] if row["operation"] == "hmp_flatview"]
    for phase, hmp, layout in (("before", hmps[0], layouts[0]), ("after", hmps[-1], layouts[-1])):
        snapshot["hmp_"+phase+"_ref"] = put_blob("hmp-"+phase+".txt",
            json.loads(slice_bytes(hmp["response"]))["return"].encode())
        snapshot["layout_"+phase+"_ref"] = put_blob("layout-"+phase+".txt",
            json.loads(slice_bytes(layout["response"]))["return"].encode())
    diagnostic = (f"Loading driver at 0x{candidate['loaded_base']:x} EntryPoint=0x{candidate['entry_address']:x} fixture.efi\n").encode()
    diagnostic_ref = put_blob("prior/debug.bin", diagnostic)
    admitted_candidate = {**entry.diagnostic_candidate(entry.parse_diagnostic(diagnostic, "fixture.efi"),
                                                     entry.parse_pe(pinned, 32)),
                          "prior_run_id": "prior", "diagnostic_ref": diagnostic_ref}
    mapping_inputs, artifacts = {}, {}
    for name in set(entry.ARTIFACT_LIMITS)-{"expanded_cpu", "invocation"}:
        artifacts[name] = put_blob("inputs/"+name, blobs[inputs[name]["path"]])
        mapping_inputs[name] = {"admission_ref": artifacts[name], "probe_ref": inputs[name],
                                "length_and_sha256_equal": True}
    for name in ("expanded_cpu", "invocation"):
        artifacts[name] = put_blob("prior/"+name+".json", {"scope": "synthetic prior hint only"})
    admission_profile = {key: profile[key] for key in ("source_commit", "assembled_patch_sha256", "diagnostic_image_name")}
    admission_profile.update(machine=capture.admission_machine(invocation_profile),
                             accelerator="tcg", cpu="qemu64", vcpus=1,
                             ram_bytes=512 << 20, artifacts=artifacts)
    pe = entry.parse_pe(pinned, 32)
    admission = {**entry.report("ADMIT", "prior_candidate_inputs_checked"),
        "profile_sha256": entry.profile_digest(admission_profile), "candidate": admitted_candidate,
        "pe": {name: getattr(pe, name) for name in ("image_base", "image_size", "header_size",
                                                   "entry_rva", "entry_file_offset", "entry_length")}}
    prior_keys = ("argv async_events candidate capture_complete checkpoints claims cleanup configured_cpu_expansion "
        "cpu_expansion_origin esp_validation final_vars finished_utc initial_vars input_pins_unchanged_after_run kind "
        "late_qmp_records lifecycle_deadline_met message_count observation_scope observer operations owned_pid profile "
        "profile_preconditions_met profile_sha256 quit_result raw_files reason reset_cpus reset_ram_layout_text "
        "reset_register_text retained_stream_bytes schema_version started_utc status stream_errors streams_complete_to_eof "
        "transport_eof_observations").split()
    prior = dict.fromkeys(prior_keys)
    plan = json.loads(blobs[host["plan_ref"]["path"]])
    prior.update(schema_version=1, kind="boot_profile_probe_v0", status="CANDIDATE_RETAINED",
        argv=plan["argv"],
        profile=profile, profile_sha256=entry.profile_digest(profile), capture_complete=False,
        profile_preconditions_met=False, claims={name: False for name in entry.CLAIM_NAMES},
        candidate={key: value for key, value in admitted_candidate.items() if key not in ("prior_run_id", "diagnostic_ref")},
        raw_files=[{**diagnostic_ref, "path": "debug.bin"}])
    mapping = {"admission_profile_sha256": entry.profile_digest(admission_profile),
        "claims": {name: False for name in entry.CLAIM_NAMES}, "inputs": mapping_inputs,
        "opaque_expanded_cpu_ref": artifacts["expanded_cpu"], "opaque_invocation_ref": artifacts["invocation"],
        "probe_profile_ref": host["profile_ref"], "probe_profile_sha256": entry.profile_digest(profile),
        "probe_report_ref": put_blob("prior/report.json", prior),
        "scope": "field-by-field mapping of the actual prior probe to existing admission subset; no fresh C0 or runtime qualification",
        "whole_unmodified_diagnostic_ref": diagnostic_ref}
    argv_ref = put_blob("c0-argv.json", plan["argv"])
    end = {"status": "PASS", "reason": "synthetic_complete", "reaped": True, "returncode": 0,
        "actions": [], "grace": "exited",
        "streams": [{"name": name, "eof": True, "error": None} for name in cap.STREAMS]}
    # CAP1 is prior-profile evidence, never a substitute for this fixture's fresh
    # raw C0 transcript and actual validated synthetic host-state record.
    def cap_blob(name, value):
        return put_blob("prior-cap1/" + name, value) | {"path": name}

    observations = cap.empty_observations()
    observations.update({key: cap_blob(key, b"synthetic prior capability") for key in cap.OBS_REFS})
    if invocation_profile == capture.VAPIC_OFF_INVOCATION_PROFILE:
        from test_run0_rsp_capability import LAYOUT
        observations["layout_ref"] = cap_blob("prior-layout_ref", LAYOUT.encode())
    observations.update(realized=True, phys_bits=40, rsp_thread="01", physical_mode=1)
    capability_report = {"schema_version": 1, "kind": "run0_reset_capability_v0", "run_id": "prior-cap",
        "profile_ref": cap_blob("profile.json", profile),
        "observer_ref": cap_blob(host["observer_ref"]["path"], b"synthetic prior observer"),
        "source_dossier_ref": cap_blob("source-dossier.json", blobs[host["source_ref"]["path"]]),
        "argv_ref": cap_blob("argv.json", plan["argv"]), "raw_refs": [],
        "observations": observations, "operations": [], "termination": copy.deepcopy(end),
        "claims": dict(cap.FALSE_CLAIMS), "fresh_c0_verified": False}
    operations = []
    for op in control["operations"]:
        row = {key: op[key] for key in ("seq", "protocol", "operation", "started_ns", "finished_ns", "result")}
        row["request_ref"] = put_blob(f"operation-{op['seq']}-request.bin", slice_bytes(op["request"]))
        row["response_ref"] = (None if op["response"] is None else
            put_blob(f"operation-{op['seq']}-response.bin", slice_bytes(op["response"])))
        operations.append(row)
    report = {"schema_version": 1, "kind": "run0_c0_inspection_subset_v0", "run_id": "witness",
        "profile_ref": host["profile_ref"], "observer_ref": host["observer_ref"],
        "source_dossier_ref": host["source_ref"], "capability_ref": put_blob("prior-cap1/report.json", capability_report),
        "prior_admission_ref": put_blob("admission.json", admission),
        "profile_mapping_ref": put_blob("mapping.json", mapping), "argv_ref": argv_ref,
        "raw_refs": [control[name] for name in ("raw_qmp_in_ref", "raw_qmp_out_ref", "raw_rsp_in_ref", "raw_rsp_out_ref")]+
                    [put_blob("vars.fd", blobs[inputs["initial_vars"]["path"]])],
        "operations": operations, "checkpoint": snapshot, "termination": end,
        "claims": dict(d.FALSE_CLAIMS), "fresh_c0_verified": False, "remaining_checkpoints": ["C1", "C2"]}
    host_streams = json.loads(blobs[host["termination"]["streams_ref"]["path"]])
    for row in host_streams["rows"]:
        if row["name"] in ("qmp", "rsp", "serial", "debug", "qemu_stdout", "qemu_stderr") and row["raw_ref"] not in report["raw_refs"]:
            report["raw_refs"].append(row["raw_ref"])
    host_ref = put_blob("host-report.json", host)
    prerequisite = witness.validate_report(host_ref, blobs)
    report_ref = put_blob("c0-report.json", report)
    return report, report_ref, blobs, prerequisite, put_blob


class DecoderControls(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(d, "C0D implementation is absent: expected gate-first RED")

    def reject(self, status, reason, function, *args, **kwargs):
        with self.assertRaises(d.C0DecodeError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.status, status)
        self.assertIn(reason, raised.exception.reason)

    def walk(self, source=None, state=None, ranges=((0, 0x400000),)):
        return d._Walker(mode() if state is None else state,
                         MappingProxyType(tables() if source is None else source), ranges)

    def test_c0d01_exact_types_and_checked_arithmetic(self):
        for value in (True, -1, 1 << 64, 1.0, "1"):
            self.reject("DENY", "integer", d._integer, value)
        for start, length in ((0, 0), (0, -1), (U64, 2), (True, 1), (0, True)):
            self.reject("DENY", "", d._span, start, length)
        self.assertEqual(d._span(U64, 1), (U64, 1 << 64))
        for width in (True, 31, 53):
            self.reject("DENY", "", self.walk, state=mode(phys_bits=width))
        self.assertEqual(self.walk().translate(0, 1)[0]["translation"]["physical"], 0x8000)

    def test_c0d02_mode_and_missing_runtime_authority(self):
        for name in ("phys_bits", "a20", "no_npt", "cr3"):
            state = mode(); del state[name]
            self.reject("INCOMPLETE", "mode_missing", self.walk, state=state)
        for bit in (12, 17, 20, 21, 22, 23, 24):
            self.reject("INCOMPLETE", "mode_unsupported", self.walk,
                      state=mode(cr4=(1 << 5) | (1 << bit)))
        for name, value in (("cpl", 3), ("cs64", False), ("a20", 0), ("no_npt", False),
                            ("no_svm_guest", False), ("no_smm", False)):
            self.reject("INCOMPLETE", "mode_unsupported", self.walk, state=mode(**{name: value}))
        for register, bits in (("cr0", (0, 31)), ("cr4", (5,)), ("efer", (8, 10))):
            for bit in bits:
                state = mode(); state[register] &= ~(1 << bit)
                self.reject("INCOMPLETE", "mode_unsupported", self.walk, state=state)
        self.reject("DENY", "mode_type", self.walk, state=mode(a20=True))

    def test_c0d03_cr3_reserved_ignored_and_root_zero(self):
        for width in (32, 36, 52):
            for bit in range(width, 64):
                self.reject("DENY", "cr3_reserved", self.walk,
                          state=mode(phys_bits=width, cr3=0x1000 | (1 << bit)))
        for bit in range(12):
            self.assertEqual(self.walk(state=mode(cr3=0x1000 | (1 << bit))).translate(0, 1)[0]
                             ["translation"]["physical"], 0x8000)
        source = tables(); source[0] = source.pop(0x1000)
        self.assertEqual(self.walk(source, mode(cr3=0)).translate(0, 1)[0]
                         ["translation"]["path"][0]["frame"], 0)
        self.reject("DENY", "ram", self.walk, source, mode(cr3=0), ((4096, 0x400000),))

    def test_c0d04_pml4_bit_mutations(self):
        for bit in (*range(40, 52), 7):
            self.reject("DENY", "entry_reserved", self.walk(changed(tables(), 0x1000, 0,
                      0x2007 | (1 << bit))).translate, 0, 1)
        for bit in (6, 8, 9, 10, 11, *range(52, 63)):
            result = self.walk(changed(tables(), 0x1000, 0, 0x2007 | (1 << bit))).translate(0, 1)
            self.assertEqual(result[0]["translation"]["physical"], 0x8000)
        self.reject("DENY", "entry_reserved", self.walk(
            changed(tables(), 0x1000, 0, 0x2007 | (1 << 63)), mode(efer=0x500)).translate, 0, 1)

    def test_c0d05_pdpt_subset_stops_before_child(self):
        walker = self.walk(changed(tables(), 0x2000, 0, 0x87))
        self.reject("INCOMPLETE", "one_gib", walker.translate, 0, 1)
        self.assertEqual(walker.lookups, [0x1000, 0x2000])
        for bit in (*range(40, 52),):
            self.reject("DENY", "entry_reserved", self.walk(
                changed(tables(), 0x2000, 0, 0x3007 | (1 << bit))).translate, 0, 1)
        self.assertEqual(self.walk().translate(0, 1)[0]["translation"]["page_bytes"], 4096)

    def test_c0d06_two_mib_pat_pse_and_boundaries(self):
        source = changed(tables(True), 0x3000, 0, 0x201087)
        result = self.walk(source).translate(0x1fffff, 1)[0]["translation"]
        self.assertEqual((result["physical"], result["page_bytes"]), (0x3fffff, 0x200000))
        self.assertEqual(self.walk(source).translate(0, 1)[0]["translation"]["physical"], 0x200000)
        source = changed(source, 0x3000, 1, 0x87)
        crossing = self.walk(source).translate(0x1fffff, 2)
        self.assertEqual([(r["translation"]["physical"], r["translation"]["length"])
                          for r in crossing], [(0x3fffff, 1), (0, 1)])
        for bit in (*range(13, 21), *range(40, 52)):
            self.reject("DENY", "entry_reserved", self.walk(
                changed(tables(True), 0x3000, 0, 0x200087 | (1 << bit))).translate, 0, 1)

    def test_c0d07_pointer_and_four_kib_leaf_flags(self):
        for bit in (7, 9, 10, 11, *range(52, 63)):
            result = self.walk(changed(tables(), 0x4000, 0, 0x8007 | (1 << bit))).translate(0, 1)
            self.assertEqual(result[0]["translation"]["physical"], 0x8000)
        for address in (0x3000, 0x4000):
            value = 0x4007 if address == 0x3000 else 0x8007
            for bit in range(40, 52):
                self.reject("DENY", "entry_reserved", self.walk(
                    changed(tables(), address, 0, value | (1 << bit))).translate, 0, 1)

    def test_c0d08_nonpresent_ignores_all_other_bits(self):
        for index, address in enumerate((0x1000, 0x2000, 0x3000, 0x4000)):
            walker = self.walk(changed(tables(), address, 0, U64 ^ 1))
            self.reject("INCOMPLETE", "unmapped", walker.translate, 0, 1)
            self.assertEqual(walker.lookups, [0x1000, 0x2000, 0x3000, 0x4000][:index+1])
            self.assertEqual(self.walk().translate(0, 1)[0]["translation"]["physical"], 0x8000)

    def test_c0d09_permissions_at_every_ancestor(self):
        for address, value in ((0x1000, 0x2007), (0x2000, 0x3007),
                               (0x3000, 0x4007), (0x4000, 0x8007)):
            for wp in (0, 1):
                state = mode(cr0=(1 << 31) | (wp << 16) | 1)
                row = self.walk(changed(tables(), address, 0, value & ~6), state).translate(0, 1)[0]
                self.assertFalse(row["translation"]["writable"])
                self.assertFalse(row["translation"]["user"])
                self.assertEqual(row["cpl0_writable"], not wp)
                self.assertTrue(row["cpl0_readable"])
            row = self.walk(changed(tables(), address, 0, value | (1 << 63))).translate(0, 1)[0]
            self.assertFalse(row["translation"]["executable"])
            self.assertTrue(row["cpl0_readable"])
            self.reject("DENY", "entry_reserved", self.walk(
                changed(tables(), address, 0, value | (1 << 63)), mode(efer=0x500)).translate, 0, 1)

    def test_c0d10_canonical_edges_and_splits(self):
        for start, length in ((1 << 47, 1), ((1 << 47)-1, 2), (U64, 2)):
            walker = self.walk()
            self.reject("DENY", "", walker.translate, start, length)
            self.assertEqual(walker.lookups, [])
        self.assertEqual([x["translation"]["length"] for x in self.walk().translate(0, 4096)],
                         [2048, 2048])
        self.assertEqual([x["translation"]["length"] for x in self.walk().translate(4090, 20)],
                         [6, 14])
        high = tables(root_index=256)
        self.assertEqual(self.walk(high).translate(0xffff800000000000, 1)[0]
                         ["translation"]["physical"], 0x8000)
        for start in ((1 << 47)-1, U64):
            self.assertEqual(d._span(start, 1)[0], start)
            edge = {0x1000: frame({(start >> 39) & 511: 0x2007}),
                    0x2000: frame({511: 0x3007}), 0x3000: frame({511: 0x4007}),
                    0x4000: frame({511: 0x8007})}
            self.assertEqual(self.walk(edge).translate(start, 1)[0]["translation"]["physical"], 0x8fff)

    def test_c0d11_ram_identity_and_complete_frame_admission(self):
        for ranges in (((0x1000, 0x1fff),), ((0, 0x8500),), ((0, 0x8000), (0x8001, 0x10000))):
            walker = self.walk(ranges=ranges) if ranges[0][1] >= 0x2000 else None
            if walker is None:
                self.reject("DENY", "ram", self.walk, ranges=ranges)
            else:
                self.reject("DENY", "ram", walker.translate, 0, 4096)
        layout = ('FlatView #0\n AS "memory", root: system\n AS "cpu-memory-0", root: system\n'
                  ' Root memory region: system\n'
                  '  0000000000000000-00000000003fffff (prio 0, ram): pc.ram\n')
        self.assertEqual(d._layout(layout.encode()), ((0, 0x400000),))
        for bad in (layout.replace('cpu-memory-0', 'cpu-memory-1'),
                    layout.replace('(prio 0, ram)', '(prio 0, romd)'),
                    layout.replace('(prio 0, ram)', '(prio 0, nv-ram)'),
                    layout.replace('(prio 0, ram)', '(prio 0, i/o)'),
                    layout.replace('pc.ram', 'pc.ram @0000000000001000')):
            self.reject("DENY", "", d._layout, bad.encode())

    def test_c0d12_shared_frames_cycles_and_exact_caps(self):
        walker = self.walk()
        walker.translate(0, 1); walker.translate(4096, 1)
        self.assertEqual(walker.lookups, [0x1000, 0x2000, 0x3000, 0x4000])
        self.reject("DENY", "frame_level", self.walk(changed(tables(), 0x1000, 0, 0x1007)).translate, 0, 1)
        many = {0x1000: frame({0: 0x2007}), 0x2000: frame({0: 0x3007}),
                0x3000: frame({i: (0x4000+i*4096)|7 for i in range(30)})}
        many.update({0x4000+i*4096: frame({0: 0x100007}) for i in range(30)})
        walker = self.walk(many)
        for i in range(29):
            walker.translate(i << 21, 1)
        self.assertEqual(len(walker.lookups), 32)
        self.reject("INCOMPLETE", "frames_limit", walker.translate, 29 << 21, 1)
        self.assertEqual(len(walker.lookups), 32)
        for name, limit in (("frames", 32), ("objects", 32), ("translations", 128),
                            ("operations", 512), ("other_bytes", 65536), ("retained_bytes", 33554432)):
            budget = d._Counts(); budget.charge(name, limit)
            self.reject("INCOMPLETE", "limit", budget.charge, name, 1)
            self.assertEqual(budget.values[name], limit)
        exhausted = self.walk()
        exhausted.counts.charge("translations", 128)
        self.reject("INCOMPLETE", "translations_limit", exhausted.translate, 0, 1)
        self.assertEqual(exhausted.lookups, [])
        snapshot, blobs, index, pinned, candidate = snapshot_fixture()
        observed = d._Blobs(blobs)
        reads = d._SnapshotReads(snapshot, observed, d.validate_c0_rsp(index, blobs),
                                 mode(), ((0, 0x400000),))
        reads.counts.charge("other_bytes", 65536)
        self.reject("INCOMPLETE", "other_bytes_limit", reads.object, "pe_header", 0x200000, 64)
        self.assertEqual(reads.walker.lookups, [])
        self.assertNotIn("frame-1000-first.bin", observed.verified)

    def test_c0d13_recorded_frames_rechecks_and_read_identity(self):
        payload = frame({0: 0x2007})
        reads = tuple(d._MemoryRead(i+1, 0x1000+(i % 2)*2048,
                                   payload[(i % 2)*2048:(i % 2+1)*2048]) for i in range(4))
        self.assertEqual(d._frame_bytes(0x1000, payload, payload, reads), payload)
        self.reject("INCOMPLETE", "", d._frame_bytes, 0x1000, payload[:-1], payload, reads)
        self.reject("INCOMPLETE", "changed", d._frame_bytes, 0x1000, payload,
                  bytes(4096), reads)
        self.reject("DENY", "read_identity", d._frame_bytes, 0x1000, payload, payload,
                  (reads[0], reads[1], reads[0], reads[1]))
        wrong = (reads[0], d._MemoryRead(2, 0x1000, reads[1].data), *reads[2:])
        self.reject("DENY", "read_identity", d._frame_bytes, 0x1000, payload, payload, wrong)
        index, blobs = rsp_fixture()
        observed = d.validate_c0_rsp(index, blobs)
        self.assertEqual(observed["candidate"], 0x100000)
        self.assertEqual(observed["before_registers"], observed["after_registers"])
        self.assertEqual(len(observed["before_sequences"]), 29)
        for name in ("physical_mode_enable", "physical_mode_query"):
            bad = copy.deepcopy(index)
            row = next(row for row in bad["operations"] if row["operation"] == name)
            row["operation"] = "foreign"
            self.reject("DENY", "rsp", d.validate_c0_rsp, bad, blobs)
        for change in ("missing", "pending", "early", "duplicate", "slice", "overlap"):
            bad = copy.deepcopy(index)
            ack = next(row for row in bad["operations"] if row["operation"] == "acknowledge_stop")
            if change == "missing":
                bad["operations"].remove(ack)
            elif change == "pending":
                ack.update(result="pending", finished_ns=None)
            elif change == "early":
                ack["started_ns"] = bad["events"][0]["received_ns"]-1
            elif change == "duplicate":
                bad["operations"].insert(bad["operations"].index(ack)+1, copy.deepcopy(ack))
            elif change == "slice":
                ack["request"]["offset"] -= 1
            else:
                ack["finished_ns"] = bad["operations"][bad["operations"].index(ack)+1]["started_ns"]+1
            self.reject("INCOMPLETE" if change in ("missing", "pending") else "DENY",
                        "", d.validate_c0_rsp, bad, blobs)
        repeated, repeated_blobs = rsp_fixture(repeated_setup=True)
        self.reject("DENY", "setup", d.validate_c0_rsp, repeated, repeated_blobs)
        missing, missing_blobs = rsp_fixture(same_stop_mode=False)
        self.reject("INCOMPLETE", "same_stop_mode", d.validate_c0_rsp, missing, missing_blobs)
        snapshot, blobs, index, pinned, candidate = snapshot_fixture()
        replay = d.validate_c0_rsp(index, blobs)
        result, translations = d._decode_objects(snapshot, d._Blobs(blobs), replay, mode(),
                                                  ((0, 0x400000),), pinned, candidate)
        self.assertEqual(result["get_memory_map"], 0x212003)
        self.assertEqual(len(translations), 8)
        for change in ("reused", "translation", "changed", "missing", "level"):
            bad = copy.deepcopy(snapshot)
            if change == "reused":
                bad["objects"][0]["read_sequences"][1] = bad["objects"][0]["read_sequences"][0]
            elif change == "translation":
                bad["translations"][0]["path"][0]["index"] = False
            elif change == "changed":
                bad["objects"][0]["recheck_ref"] = blob(blobs, "changed-object.bin", bytes(64))
            elif change == "missing":
                bad["objects"].pop()
            else:
                bad["tables"][0]["level"] = 3
            self.reject("INCOMPLETE" if change in ("changed", "missing") else "DENY", "",
                d._decode_objects, bad, d._Blobs(blobs), replay, mode(), ((0, 0x400000),), pinned, candidate)
        for entry, status, reason in ((0, "INCOMPLETE", "unmapped"), (0x2087, "DENY", "reserved")):
            bad, poisoned_blobs, poisoned_index, pinned, candidate = snapshot_fixture(pml4_entry=entry)
            observed = d._Blobs(poisoned_blobs)
            replay = d.validate_c0_rsp(poisoned_index, poisoned_blobs)
            self.reject(status, reason, d._decode_objects, bad, observed, replay,
                        mode(), ((0, 0x400000),), pinned, candidate)
            self.assertNotIn("frame-2000-first.bin", observed.verified)
            self.assertNotIn("frame-3000-first.bin", observed.verified)

    def test_c0d14_public_efi_ieee_crc_and_pointer_bounds(self):
        self.assertEqual(d._crc32(b"123456789"), 0xcbf43926)
        self.assertEqual(d._efi("system", efi("system", 0x6000), 0x5000), 0x6000)
        self.assertEqual(d._efi("boot", efi("boot", 0x7003), 0x6000), 0x7003)
        for kind, address in (("system", 0x5000), ("boot", 0x6000)):
            original = efi(kind, 0x7000)
            for offset, value in ((0, 0), (8, 0x20070), (12, 24), (20, 1)):
                bad = bytearray(original); struct.pack_into("<I", bad, offset, value)
                bad[16:20] = bytes(4); struct.pack_into("<I", bad, 16, zlib.crc32(bad))
                self.reject("DENY", "efi", d._efi, kind, bytes(bad), address)
            for crc in (crc32c, lambda b: zlib.crc32(b[:24]), lambda b: zlib.crc32(original)):
                bad = bytearray(original); bad[16:20] = bytes(4)
                struct.pack_into("<I", bad, 16, crc(bad))
                self.reject("DENY", "efi_crc", d._efi, kind, bytes(bad), address)
            self.reject("INCOMPLETE", "efi_length", d._efi, kind, original[:-1], address)
            for bad_address in (0, 3, 1 << 47, U64-7):
                self.reject("DENY", "", d._efi, kind, original, bad_address)
        for pointer in (0, 3, 1 << 47, U64-7):
            self.reject("DENY", "", d._efi, "system", efi("system", pointer), 0x5000)

    def test_c0d15_loaded_pe_header_and_exact_entry(self):
        original = bytes(pe_fixture()); base = 0x200000
        headers = {0: original[:64], 0x80: original[0x80:0x98],
                   0x98: original[0x98:0x188], 0x188: original[0x188:0x1d8]}
        optional = bytearray(headers[0x98]); struct.pack_into("<Q", optional, 24, base)
        headers[0x98] = bytes(optional)
        entry = bytearray(original[0x420:0x440]); struct.pack_into("<Q", entry, 8, 0x201234)
        self.assertEqual(d._loaded_pe(original, base, base+0x1020, headers, bytes(entry)), base)
        bad_headers = dict(headers); bad_headers[0] = b'NO'+headers[0][2:]
        self.reject("DENY", "pe_header", d._loaded_pe, original, base, base+0x1020, bad_headers, bytes(entry))
        self.reject("DENY", "pe_entry", d._loaded_pe, original, base, base+0x1020, headers, bytes(32))
        self.reject("DENY", "pe_candidate", d._loaded_pe, original, base, base+0x1021, headers, bytes(entry))
        for target in (0x101c, 0x103c):
            bad = bytearray(original); put(bad, 0x608, 'H', 0xa000 | (target-0x1000))
            self.reject("DENY", "partial_relocation", d._loaded_pe,
                      bytes(bad), base, base+0x1020, headers, bytes(entry))

    def test_sata_off_replay_denies_legacy_prior_probe_or_capability_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            report, ref, blobs, host, put = full_fixture(
                Path(directory), capture.SATA_OFF_INVOCATION_PROFILE,
            )
            self.assertEqual(d.decode_c0("synthetic_fixture", ref, blobs, host)["status"], "PASS")
            mapping = json.loads(blobs[report["profile_mapping_ref"]["path"]])
            prior_path = mapping["probe_report_ref"]["path"]
            prior = json.loads(blobs[prior_path])
            prior["argv"][2] = "pc-q35-8.2,accel=tcg"
            mapping["probe_report_ref"] = put(prior_path, prior)
            bad = report | {"profile_mapping_ref": put("wrong-mapping.json", mapping)}
            self.assertEqual(d.decode_c0("synthetic_fixture", put("wrong-probe.json", bad),
                                         blobs, host)["reason"], "retained_argv")
        with tempfile.TemporaryDirectory() as directory:
            report, _, blobs, host, put = full_fixture(
                Path(directory), capture.SATA_OFF_INVOCATION_PROFILE,
            )
            previous = json.loads(blobs[report["capability_ref"]["path"]])
            argv = json.loads(blobs["prior-cap1/" + previous["argv_ref"]["path"]])
            argv[2] = "pc-q35-8.2,accel=tcg"
            previous["argv_ref"] = put("prior-cap1/argv.json", argv) | {"path": "argv.json"}
            bad = report | {"capability_ref": put("prior-cap1/report.json", previous)}
            self.assertEqual(d.decode_c0("synthetic_fixture", put("wrong-c0.json", bad),
                                         blobs, host)["reason"], "retained_argv")

    def test_vapic_off_replay_binds_both_prior_argv_and_layout(self):
        for target in ("probe", "capability", "layout"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                report, ref, blobs, host, put = full_fixture(
                    Path(directory), capture.VAPIC_OFF_INVOCATION_PROFILE)
                self.assertEqual(d.decode_c0("synthetic_fixture", ref, blobs, host)["status"], "PASS")
                if target == "probe":
                    mapping = json.loads(blobs[report["profile_mapping_ref"]["path"]])
                    path = mapping["probe_report_ref"]["path"]
                    prior = json.loads(blobs[path])
                    prior["argv"] = prior["argv"][:3] + prior["argv"][5:]
                    mapping["probe_report_ref"] = put(path, prior)
                    bad = report | {"profile_mapping_ref": put("changed-mapping.json", mapping)}
                    reason = "retained_argv"
                else:
                    prior = json.loads(blobs["prior-cap1/report.json"])
                    if target == "capability":
                        argv = json.loads(blobs["prior-cap1/" + prior["argv_ref"]["path"]])
                        argv = argv[:3] + argv[5:]
                        prior["argv_ref"] = put("prior-cap1/argv.json", argv) | {"path": "argv.json"}
                        reason = "retained_argv"
                    else:
                        name = prior["observations"]["layout_ref"]["path"]
                        raw = blobs["prior-cap1/" + name].replace(b"vga", b"kvmvapic")
                        prior["observations"]["layout_ref"] = put("prior-cap1/" + name, raw) | {"path": name}
                        reason = "vapic_off_device_visible"
                    bad = report | {"capability_ref": put("prior-cap1/report.json", prior)}
                result = d.decode_c0("synthetic_fixture", put("bad-successor.json", bad), blobs, host)
                self.assertEqual((result["status"], result["reason"]), ("DENY", reason))

    def test_vapic_off_rejects_device_in_each_current_layout(self):
        from test_run0_rsp_capability import LAYOUT
        for phases in ((0,), (1,), (0, 1)):
            for device, reason in (("kvmvapic", "vapic_off_device_visible"),
                                   ("ich9-ahci", "sata_off_ahci_visible")):
                with self.subTest(phases=phases, device=device), tempfile.TemporaryDirectory() as directory:
                    layouts = [LAYOUT, LAYOUT]
                    for phase in phases:
                        layouts[phase] = LAYOUT.replace("vga", device)
                    report, ref, blobs, host, _ = full_fixture(
                        Path(directory), capture.VAPIC_OFF_INVOCATION_PROFILE,
                        current_layouts=tuple(layouts))
                    result = d.decode_c0("synthetic_fixture", ref, blobs, host)
                    self.assertEqual((result["status"], result["reason"]), ("DENY", reason))
        for invocation in (capture.INVOCATION_PROFILE, capture.SATA_OFF_INVOCATION_PROFILE):
            with self.subTest(legacy_profile=invocation), tempfile.TemporaryDirectory() as directory:
                layout = LAYOUT.replace("vga", "kvmvapic")
                _, ref, blobs, host, _ = full_fixture(
                    Path(directory), invocation, current_layouts=(layout, layout))
                self.assertEqual(d.decode_c0("synthetic_fixture", ref, blobs, host)["status"], "PASS")

    def test_prior_capability_namespace_has_no_current_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            report, ref, blobs, host, put = full_fixture(Path(directory))
            prior = json.loads(blobs["prior-cap1/report.json"])
            name = prior["observer_ref"]["path"]
            prior_name = "prior-cap1/" + name
            self.assertNotEqual(blobs[prior_name], blobs[name])
            self.assertEqual(d.decode_c0("synthetic_fixture", ref, blobs, host)["status"], "PASS")

            prior_bytes = blobs.pop(prior_name)
            current_bytes = blobs[name]
            # Even an exact match at the flat name must not supply prior bytes.
            self.reject("INCOMPLETE", "blob_missing", d._capability_binding, report,
                        d._Blobs(blobs | {name: prior_bytes}), json.loads(blobs[report["profile_ref"]["path"]]))
            blobs[prior_name] = prior_bytes
            self.assertEqual(blobs[name], current_bytes)

            for path in ("other/report.json", "prior-cap1/nested/report.json"):
                bad = report | {"capability_ref": put(path, prior)}
                result = d.decode_c0("synthetic_fixture", put("bad-top.json", bad), blobs, host)
                self.assertEqual((result["status"], result["reason"]), ("DENY", "capability_namespace"))
            for path in ("../" + name, "prior-cap1/" + name, "subdir/" + name):
                bad_prior = prior | {"observer_ref": prior["observer_ref"] | {"path": path}}
                bad = report | {"capability_ref": put("prior-cap1/report.json", bad_prior)}
                result = d.decode_c0("synthetic_fixture", put("bad-nested.json", bad), blobs, host)
                self.assertEqual((result["status"], result["reason"]), ("DENY", "blob_ref_value"))
            put("prior-cap1/report.json", prior)
            for path in ("prior-cap1", "prior-cap1/current.json"):
                current_in_prior = put(path, report)
                result = d.decode_c0("synthetic_fixture", current_in_prior, blobs, host)
                self.assertEqual((result["status"], result["reason"]), ("DENY", "output_namespace"))
            self.assertEqual(d.decode_c0("synthetic_fixture", ref, blobs, host)["status"], "PASS")

    def test_c0d16_strict_refs_and_incomplete_claims(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e400}', b'\xff'):
            self.reject("DENY", "json", d._json, raw)
        blobs = {}; reference = blob(blobs, "sample", b"known")
        store = d._Blobs(blobs)
        self.assertEqual(store.get(reference, 32), b"known")
        self.reject("DENY", "digest", d._Blobs({"sample": b"wrong"}).get, reference, 32)
        self.reject("DENY", "path", store.get, {**reference, "path": "../sample"}, 32)
        self.reject("INCOMPLETE", "missing", d._Blobs({}).get, reference, 32)
        empty_ref = json_blob(blobs, "unobserved.json", {})
        callbacks = []

        class HostileMapping:
            def __init__(self, values):
                self.values = values

            def __len__(self):
                callbacks.append("len")
                return len(self.values)

            def keys(self):
                callbacks.append("keys")
                return self.values.keys()

            def __getitem__(self, key):
                callbacks.append("getitem")
                return self.values[key]

        hostile_blobs = MappingProxyType(HostileMapping(blobs))
        hostile_ref = MappingProxyType(HostileMapping(empty_ref))
        self.reject("DENY", "mapping", d._Blobs, hostile_blobs)
        self.reject("DENY", "ref", d.decode_c0, "synthetic_fixture", hostile_ref, {}, None)
        self.reject("DENY", "index", d.validate_c0_rsp, MappingProxyType(HostileMapping({})), {})
        self.reject("DENY", "index", d.validate_c0_rsp,
                    {"operations": [{"request": hostile_ref}]}, {})
        self.assertEqual(d.decode_c0("synthetic_fixture", empty_ref, hostile_blobs, None)["status"], "DENY")
        self.assertEqual(callbacks, [])
        result = d.decode_c0("retained_runtime", empty_ref, blobs, None)
        self.assertEqual(result["status"], "DENY")
        self.assertTrue(all(value is False for value in result["claims"].values()))
        self.assertIs(result["fresh_c0_verified"], False)
        self.assertIs(result["atomic_snapshot"], False)
        self.reject("DENY", "origin", d.decode_c0, "invented", empty_ref, blobs, None)
        with tempfile.TemporaryDirectory() as directory:
            report, report_ref, blobs, prerequisite, put_blob = full_fixture(Path(directory))
            result = d.decode_c0("synthetic_fixture", report_ref, blobs, prerequisite)
            self.assertEqual((result["status"], result["reason"]), ("PASS", "retained_c0_decoded"))
            self.assertEqual(result["loaded_identity"]["get_memory_map"], 0x212003)
            self.assertEqual(result["origin"], "synthetic_fixture")
            self.assertTrue(all(value is False for value in result["claims"].values()))
            self.assertIs(result["fresh_c0_verified"], False)
            self.assertIs(result["device_quiescence_verified"], False)
            import run0_host_cpu_witness as host_module

            class HostileScalar:
                def __eq__(self, other):
                    callbacks.append("eq")
                    raise AssertionError("opaque export invoked caller equality")

            for name in ("origin", "report_ref", "binding", "state", "final_status"):
                forged = object.__new__(host_module.ValidatedHostState)
                for field in ("origin", "report_ref", "binding", "state", "final_status"):
                    item = getattr(prerequisite, field)
                    if field == name:
                        item = (HostileScalar() if name in ("origin", "final_status") else
                                MappingProxyType(HostileMapping({})))
                    object.__setattr__(forged, field, item)
                refused = d.decode_c0("synthetic_fixture", report_ref, blobs, forged)
                self.assertEqual(refused["status"], "DENY", (name, refused))
            self.assertEqual(callbacks, [])
            with ExitStack() as no_effects:
                for name in ("builtins.open", "os.open", "socket.socket", "subprocess.Popen",
                             "time.monotonic", "time.monotonic_ns", "time.time", "time.sleep"):
                    no_effects.enter_context(patch(name, side_effect=AssertionError("decoder acquired effects: "+name)))
                pure = d.decode_c0("synthetic_fixture", report_ref, blobs, prerequisite)
                self.assertEqual(pure, result)
            for change, status in (("missing_witness", "INCOMPLETE"), ("origin", "DENY"),
                                   ("source", "DENY"), ("cleanup", "INCOMPLETE"),
                                   ("index", "DENY"), ("unknown", "DENY")):
                bad = copy.deepcopy(report)
                witness = prerequisite
                origin = "synthetic_fixture"
                if change == "missing_witness":
                    witness = None
                elif change == "origin":
                    origin = "retained_runtime"
                elif change == "source":
                    bad["source_dossier_ref"] = put_blob("unrelated-source.txt", b"unrelated")
                elif change == "cleanup":
                    bad["termination"]["streams"][0]["eof"] = False
                elif change == "index":
                    bad["operations"][0]["request_ref"] = put_blob("unrelated-request.bin", b"{}\r\n")
                else:
                    bad["caller_override"] = True
                changed_ref = put_blob("changed-c0-report.json", bad)
                observed = d.decode_c0(origin, changed_ref, blobs, witness)
                self.assertEqual(observed["status"], status, (change, observed))
            self.assertEqual(d.decode_c0("synthetic_fixture", report_ref, blobs,
                                         prerequisite)["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
