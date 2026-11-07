"""Pure retained-byte C0 decoder; synthetic checks never establish runtime access.

No byte acquisition is implemented here. The public envelope requires the
separately validated host witness before interpreting a runtime memory record.
Private arithmetic/format helpers return interpretations, never read authority.
"""

import binascii
from dataclasses import dataclass
import hashlib
import json
import math
import re
import struct
from types import MappingProxyType

import boot_profile_inputs as entry
import boot_profile_capture as capture
import run0_rsp_capability as capability
import run0_rsp as rsp
from run0_c0_paging import (
    C0DecodeError, NeedFrame, PageWalk, U64, canonical_span as _span,
    integer as _integer, require as _require,
)


U63 = (1 << 63) - 1
REPORT_LIMIT = 1 << 20
LIMITS = MappingProxyType({"frames": 32, "objects": 32, "translations": 128,
                          "operations": 512, "other_bytes": 65536,
                          "retained_bytes": 32 << 20})
FALSE_CLAIMS = MappingProxyType({name: False for name in
                               (*entry.CLAIM_NAMES, "capture_complete", "profile_preconditions_met")})
_MAPPING = (dict, MappingProxyType)


def _fields(value, names, reason="object_fields"):
    _require(type(value) in _MAPPING and set(value) == set(names), reason)


def _json(data, limit=REPORT_LIMIT):
    _require(type(data) is bytes and len(data) <= limit, "json_bound")

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "json_duplicate_key")
            result[key] = value
        return result

    def constant(_):
        raise C0DecodeError("DENY", "json_nonfinite")

    def finite(value):
        number = float(value)
        _require(math.isfinite(number), "json_nonfinite")
        return number

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=constant, parse_float=finite)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise C0DecodeError("DENY", "json_encoding_or_syntax") from error


def _ref(value, limit):
    _fields(value, ("path", "sha256", "length"), "blob_ref_fields")
    path = value["path"]
    _require(type(path) is str and len(path) <= 240 and re.fullmatch(
        r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path) is not None and
        all(part not in (".", "..") for part in path.split("/")), "blob_path")
    _require(type(value["sha256"]) is str and
             re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None, "blob_digest_shape")
    _integer(value["length"], 0, limit)
    return dict(value)


class _Blobs:
    def __init__(self, values):
        # An external mappingproxy may wrap callback-capable user code. Only a
        # native dict is copied; its exact str/bytes contents become private.
        _require(type(values) is dict, "blob_mapping_type")
        _require(len(values) <= 4096, "blob_mapping_bound")
        snapshot = dict.copy(values)
        _require(all(type(key) is str and type(value) is bytes for key, value in snapshot.items()),
                 "blob_mapping_contents")
        self.values = MappingProxyType(snapshot)
        self.identities = {}
        self.verified = {}

    def get(self, reference, limit):
        reference = _ref(reference, limit)
        name = reference["path"]
        identity = (reference["sha256"], reference["length"])
        _require(name not in self.identities or self.identities[name] == identity,
                 "blob_conflicting_identity")
        self.identities[name] = identity
        if name in self.verified:
            return self.verified[name]
        _require(name in self.values, "blob_missing", "INCOMPLETE")
        data = self.values[name]
        _require(type(data) is bytes and len(data) == reference["length"], "blob_length")
        _require(hashlib.sha256(data).hexdigest() == reference["sha256"], "blob_digest")
        self.verified[name] = data
        return data


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class _WireToken:
    offset: int
    raw: bytes
    payload: bytes | None


def _rsp_tokens(raw):
    """Parse bounded complete ACK-mode bytes, retaining exact encoded extents."""
    _require(type(raw) is bytes and len(raw) <= LIMITS["retained_bytes"], "rsp_raw_bound")
    result, position = [], 0
    while position < len(raw):
        _require(len(result) < 3 * LIMITS["operations"] + 128, "rsp_token_limit", "INCOMPLETE")
        start = position
        if raw[position:position+1] == b"+":
            result.append(_WireToken(position, b"+", None)); position += 1
            continue
        _require(raw[position:position+1] == b"$", "rsp_packet_start")
        position += 1
        encoded = bytearray()
        decoded = bytearray()
        escaped = False
        while position < len(raw) and (escaped or raw[position] != ord("#")):
            _require(position-start < 8192-3, "rsp_packet_limit", "INCOMPLETE")
            value = raw[position]; position += 1
            encoded.append(value)
            if escaped:
                _require(len(decoded) < 4096, "rsp_payload_limit", "INCOMPLETE")
                decoded.append(value ^ 0x20); escaped = False
            elif value == ord("}"):
                escaped = True
            else:
                _require(value not in (ord("*"), ord("$")), "rsp_packet_encoding")
                _require(len(decoded) < 4096, "rsp_payload_limit", "INCOMPLETE")
                decoded.append(value)
        _require(not escaped and position+3 <= len(raw), "rsp_packet_partial", "INCOMPLETE")
        checksum = raw[position+1:position+3]
        _require(re.fullmatch(rb"[0-9a-fA-F]{2}", checksum) is not None, "rsp_checksum_shape")
        _require(sum(encoded) & 255 == int(checksum, 16), "rsp_checksum")
        position += 3
        result.append(_WireToken(start, raw[start:position], bytes(decoded)))
    return tuple(result)


def _slice(store, reference, whole_ref, token):
    _fields(reference, ("blob", "offset", "length"), "wire_slice_fields")
    _require(reference["blob"] == whole_ref, "wire_slice_source")
    offset = _integer(reference["offset"])
    length = _integer(reference["length"], 1, 65536)
    _require(offset <= whole_ref["length"] and length <= whole_ref["length"]-offset,
             "wire_slice_bounds")
    _require((offset, length) == (token.offset, len(token.raw)), "wire_slice_identity")
    # The complete raw blob is checked before tokenization; this call enforces
    # path identity too, without rehashing an immutable stream for every slice.
    _require(store.get(reference["blob"], LIMITS["retained_bytes"])[offset:offset+length]
             == token.raw, "wire_slice_bytes")


SELECTED_REGISTERS = (*range(24), *range(27, 31), 32)


def _native_index(value):
    """Snapshot the shared raw index without invoking arbitrary Mapping code."""
    count = 0

    def copy(item, depth):
        nonlocal count
        count += 1
        _require(count <= 65536 and depth <= 16, "rsp_index_bound")
        kind = type(item)
        if kind is dict:
            _require(all(type(key) is str for key in item), "rsp_index_key")
            return {key: copy(value, depth+1) for key, value in item.items()}
        if kind is list:
            return [copy(value, depth+1) for value in item]
        _require(item is None or kind in (str, int, bool), "rsp_index_value")
        return item

    _require(type(value) is dict, "rsp_index_type")
    return copy(value, 0)


def validate_c0_rsp(index, blobs):
    """Pure shared-C0 RSP replay used by both host and decoder validation.

    QMP is validated by the host module. This function consumes no transport and
    does not issue a witness; all returned values derive from supplied raw bytes.
    """
    index = _native_index(index)
    store = _Blobs(blobs)
    for name in ("raw_rsp_in_ref", "raw_rsp_out_ref"):
        _require(name in index and index[name] is not None, "rsp_raw_missing", "INCOMPLETE")
    rx_ref, tx_ref = index["raw_rsp_in_ref"], index["raw_rsp_out_ref"]
    rx = _rsp_tokens(store.get(rx_ref, LIMITS["retained_bytes"]))
    tx = _rsp_tokens(store.get(tx_ref, LIMITS["retained_bytes"]))
    _require(type(index.get("operations")) in (list, tuple) and
             len(index["operations"]) <= 512, "rsp_operation_limit", "INCOMPLETE")
    _require(type(index.get("events")) in (list, tuple) and len(index["events"]) <= 128,
             "rsp_event_limit", "INCOMPLETE")
    rows = [row for row in index["operations"] if type(row) in _MAPPING and row.get("protocol") == "rsp"]
    events = [row for row in index["events"] if type(row) in _MAPPING and row.get("protocol") == "rsp"]
    _require(len(events) == 1, "rsp_stop_missing" if not events else "rsp_stop_duplicate",
             "INCOMPLETE" if not events else "DENY")
    event = events[0]
    _fields(event, ("seq", "protocol", "received_ns", "wire", "name"), "rsp_event_fields")
    _integer(event["seq"], 1); _integer(event["received_ns"], 0, U63)
    _require(event["name"] == "T05thread:01;", "rsp_stop_identity")
    for row in rows:
        _fields(row, ("seq", "protocol", "operation", "request", "response", "started_ns",
                      "finished_ns", "result"), "rsp_operation_fields")
        _integer(row["seq"], 1); _integer(row["started_ns"], 0, U63)
        _require(row["result"] in ("ok", "error", "timeout", "pending"), "rsp_result")
        _require(row["result"] == "ok" and row["finished_ns"] is not None,
                 "rsp_operation_incomplete", "INCOMPLETE")
        _integer(row["finished_ns"], row["started_ns"], U63)
        _require(row["finished_ns"]-row["started_ns"] <= 5_000_000_000,
                 "rsp_response_deadline", "INCOMPLETE")
    _require([row["seq"] for row in rows] == sorted({row["seq"] for row in rows}),
             "rsp_sequence")
    _require(all(left["finished_ns"] <= right["started_ns"] for left, right in zip(rows, rows[1:])),
             "rsp_operation_overlap")
    fixed = {"supported": (b"qSupported:qXfer:features:read+", None),
             "thread_first": (b"qfThreadInfo", b"m01"), "thread_next": (b"qsThreadInfo", b"l"),
             "thread_current": (b"qC", b"QC01"), "thread_general": (b"Hg01", b"OK"),
             "thread_continue": (b"Hc01", b"OK"), "reset_registers": (b"g", None),
             "qemu_supported": (b"qqemu.Supported", None),
             "physical_mode_query": (b"qqemu.PhyMemMode", None),
             "physical_mode_enable": (b"Qqemu.PhyMemMode:1", b"OK")}
    parsed, i, j, position = {}, 0, 0, 0
    breakpoint = resume = acknowledgment = clear = None
    candidate = None
    physical_mode, enabled, verified, verified_after_stop = 0, False, False, False
    registers, memory = [], []
    xml = {"feature_target": bytearray(), "feature_core": bytearray()}
    xml_done = set()
    while position < len(rows):
        row = rows[position]; name = row["operation"]
        _require(type(name) is str, "rsp_operation_name")
        _require(i < len(tx) and j < len(rx), "rsp_wire_missing", "INCOMPLETE")
        request_token = tx[i]; i += 1
        _slice(store, row["request"], tx_ref, request_token)
        _require(request_token.payload is not None, "rsp_request_packet")
        command = request_token.payload
        _require(request_token.raw == rsp.encode_packet(command), "rsp_request_encoding")
        _require(rx[j].raw == b"+", "rsp_request_ack"); request_ack = rx[j]; j += 1
        if name == "resume":
            _require(command == b"c" and breakpoint is not None and resume is None and
                     clear is None, "rsp_resume")
            _slice(store, row["response"], rx_ref, request_ack)
            _require(j < len(rx), "rsp_stop_missing", "INCOMPLETE")
            stop_token = rx[j]; j += 1
            _slice(store, event["wire"], rx_ref, stop_token)
            _require(stop_token.payload == b"T05thread:01;", "rsp_stop_identity")
            _require(row["finished_ns"] <= event["received_ns"], "rsp_stop_order")
            _require(event["received_ns"]-row["started_ns"] <= 60_000_000_000,
                     "rsp_stop_deadline", "INCOMPLETE")
            _require(position+1 < len(rows) and rows[position+1]["operation"] == "acknowledge_stop",
                     "rsp_stop_ack_missing", "INCOMPLETE")
            acknowledgment = rows[position+1]
            _require(i < len(tx) and tx[i].raw == b"+", "rsp_stop_ack_byte")
            _slice(store, acknowledgment["request"], tx_ref, tx[i]); i += 1
            _require(acknowledgment["response"] is None and
                     event["received_ns"] < acknowledgment["started_ns"], "rsp_stop_ack_order")
            parsed[acknowledgment["seq"]] = {**dict(acknowledgment), "request_payload": b"+",
                                            "response_payload": None}
            resume = row
            reply = None
            position += 1
        else:
            _require(j < len(rx), "rsp_response_missing", "INCOMPLETE")
            response_token = rx[j]; j += 1
            _slice(store, row["response"], rx_ref, response_token)
            _require(response_token.payload is not None, "rsp_response_packet")
            reply = response_token.payload
            _require(reply != b"" and re.fullmatch(rb"E[0-9a-fA-F]{2}", reply) is None,
                     "rsp_response_error", "INCOMPLETE")
            _require(i < len(tx) and tx[i].raw == b"+", "rsp_response_ack"); i += 1
            if name in fixed:
                expected_request, expected_reply = fixed[name]
                _require(command == expected_request and
                         (expected_reply is None or reply == expected_reply), "rsp_fixed_operation")
                if name not in ("physical_mode_query", "physical_mode_enable"):
                    _require(resume is None, "rsp_setup_after_resume")
                if name == "physical_mode_enable":
                    _require(not enabled and not memory, "rsp_physical_mode_change")
                    physical_mode, enabled = 1, True
                elif name == "physical_mode_query":
                    _require(not memory and reply == str(physical_mode).encode(), "rsp_physical_mode_reply")
                    verified = enabled and reply == b"1"
                    if resume is not None:
                        _require(not verified_after_stop and verified, "rsp_same_stop_mode_query")
                        verified_after_stop = True
                elif name == "qemu_supported":
                    tokens = reply.split(b";")
                    _require(len(tokens) == len(set(tokens)) and b"PhyMemMode" in tokens,
                             "rsp_physical_mode_capability")
                elif name == "reset_registers":
                    _require(re.fullmatch(rb"[0-9a-fA-F]{1216}", reply) is not None,
                             "rsp_reset_registers")
                elif name == "supported":
                    features = reply.split(b";")
                    keys = [part.split(b"=")[0].rstrip(b"+-") for part in features]
                    _require(all(re.fullmatch(rb"[A-Za-z0-9_.:-]+(?:=[A-Za-z0-9_.:-]+|[+-])?", part)
                                 for part in features) and len(keys) == len(set(keys)), "rsp_supported")
                    sizes = [part[11:] for part in features if part.startswith(b"PacketSize=")]
                    _require(len(sizes) == 1 and re.fullmatch(rb"[0-9a-fA-F]{1,8}", sizes[0])
                             and int(sizes[0], 16) >= 4096 and b"qXfer:features:read+" in features,
                             "rsp_supported_missing", "INCOMPLETE")
            elif name in xml:
                _require(resume is None and name not in xml_done, "rsp_xml_order")
                annex = b"target.xml" if name == "feature_target" else b"i386-64bit.xml"
                _require(command == b"qXfer:features:read:"+annex+b":"+
                         f"{len(xml[name]):x},400".encode(), "rsp_xml_request")
                _require(reply[:1] in (b"m", b"l") and 1 < len(reply) <= 1025, "rsp_xml_reply")
                _require(sum(map(len, xml.values())) + len(reply)-1 <= 16384,
                         "rsp_xml_limit", "INCOMPLETE")
                xml[name].extend(reply[1:])
                if reply[:1] == b"l":
                    xml_done.add(name)
            elif name == "hardware_breakpoint_set":
                match = re.fullmatch(rb"Z1,([0-9a-f]{1,16}),1", command)
                _require(match is not None and reply == b"OK" and breakpoint is None and
                         resume is None, "rsp_breakpoint")
                candidate = int(match[1], 16); _span(candidate, 1)
                _require(command == f"Z1,{candidate:x},1".encode(), "rsp_breakpoint_encoding")
                breakpoint = row
            elif name == "hardware_breakpoint_clear":
                _require(resume is not None and clear is None and command ==
                         f"z1,{candidate:x},1".encode() and reply == b"OK" and
                         position == len(rows)-1, "rsp_breakpoint_clear")
                clear = row
            elif name == "register_read":
                match = re.fullmatch(rb"p([0-9a-f]{1,2})", command)
                _require(match is not None and resume is not None and clear is None, "rsp_register_request")
                number = int(match[1], 16)
                _require(number in SELECTED_REGISTERS and command == f"p{number:x}".encode(),
                         "rsp_register_inventory")
                size = 4 if 17 <= number <= 23 else 8
                _require(re.fullmatch(rb"[0-9a-fA-F]{"+str(size*2).encode()+rb"}", reply) is not None,
                         "rsp_register_width")
                registers.append((row["seq"], number, int.from_bytes(bytes.fromhex(reply.decode()), "little")))
            elif name == "physical_read":
                match = re.fullmatch(rb"m([0-9a-f]{1,16}),([0-9a-f]{1,3})", command)
                _require(match is not None and resume is not None and clear is None, "rsp_memory_request")
                address, size = int(match[1], 16), int(match[2], 16)
                _integer(size, 1, 2048)
                _require(size-1 <= U64-address and command == f"m{address:x},{size:x}".encode(),
                         "rsp_memory_span")
                _require(enabled and verified, "rsp_physical_mode_missing", "INCOMPLETE")
                _require(verified_after_stop, "rsp_same_stop_mode_missing", "INCOMPLETE")
                _require(re.fullmatch(rb"[0-9a-fA-F]{"+str(size*2).encode()+rb"}", reply) is not None,
                         "rsp_memory_length")
                memory.append(row["seq"])
            else:
                raise C0DecodeError("DENY", "rsp_operation_forbidden")
        parsed[row["seq"]] = {**dict(row), "request_payload": command, "response_payload": reply}
        position += 1
    _require(i == len(tx) and j == len(rx), "rsp_unindexed_bytes")
    _require(resume is not None and clear is not None and memory, "rsp_c0_incomplete", "INCOMPLETE")
    _require(clear["finished_ns"]-event["received_ns"] <= 60_000_000_000,
             "rsp_stop_deadline", "INCOMPLETE")
    before = [row for row in registers if row[0] < min(memory)]
    after = [row for row in registers if row[0] > max(memory)]
    _require(len(before)+len(after) == len(registers) and
             tuple(row[1] for row in before) == tuple(row[1] for row in after) == SELECTED_REGISTERS,
             "rsp_register_acquisitions")
    before_values = {number: value for _, number, value in before}
    after_values = {number: value for _, number, value in after}
    _require(before_values == after_values, "rsp_register_changed", "INCOMPLETE")
    _require(before_values[16] == candidate, "rsp_candidate_rip")
    _require(xml_done == set(xml), "rsp_xml_missing", "INCOMPLETE")
    setup = [row["operation"] for row in rows if row["seq"] < breakpoint["seq"]]
    setup_expected = ["supported", "thread_first", "thread_next", "thread_current", "thread_general", "thread_continue",
                      *(["feature_target"]*setup.count("feature_target")),
                      *(["feature_core"]*setup.count("feature_core")),
                      *(["reset_registers"]*setup.count("reset_registers")), "qemu_supported",
                      "physical_mode_query", "physical_mode_enable", "physical_mode_query"]
    _require(setup == setup_expected and setup.count("reset_registers") <= 1 and
             all(row["seq"] < breakpoint["seq"] or row["operation"] == "physical_mode_query"
                 and row["seq"] > acknowledgment["seq"]
                 for row in rows if row["operation"] in (*fixed, *xml)),
             "rsp_setup_order")
    try:
        target = rsp.decode_target_description(bytes(xml["feature_target"]), bytes(xml["feature_core"]))
        for row in rows:
            if row["operation"] == "reset_registers":
                reset = rsp.decode_reset_registers(parsed[row["seq"]]["response_payload"], target)
                _require(reset.values[16] == 0xfff0, "rsp_reset_rip")
    except capture.ProbeError as error:
        raise C0DecodeError(error.status, error.reason) from error
    return _freeze({"breakpoint_seq": breakpoint["seq"], "resume_seq": resume["seq"],
        "acknowledge_stop_seq": acknowledgment["seq"], "candidate": candidate,
        "stop_event": dict(event), "before_registers": before_values, "after_registers": after_values,
        "before_sequences": [row[0] for row in before], "after_sequences": [row[0] for row in after],
        "operations": parsed})


class _Counts:
    def __init__(self):
        self.values = {name: 0 for name in LIMITS}

    def charge(self, name, length):
        _require(type(name) is str and name in LIMITS, "counter_name")
        _integer(length)
        _require(length <= LIMITS[name] - self.values[name], name + "_limit", "INCOMPLETE")
        self.values[name] += length


def _mode(state):
    names = {"phys_bits", "cr0", "cr3", "cr4", "efer", "cpl", "cs64", "a20",
             "no_npt", "no_svm_guest", "no_smm"}
    _require(type(state) in _MAPPING, "mode_type")
    _require(set(state) <= names, "mode_fields")
    _require(set(state) == names, "mode_missing", "INCOMPLETE")
    for name in ("cr0", "cr3", "cr4", "efer"):
        _integer(state[name])
    _integer(state["phys_bits"], 32, 52)
    _require(type(state["cpl"]) is int and 0 <= state["cpl"] <= 3 and
             type(state["a20"]) is int and state["a20"] in (0, 1), "mode_type")
    for name in ("cs64", "no_npt", "no_svm_guest", "no_smm"):
        _require(type(state[name]) is bool, "mode_type")
    unsupported = sum(1 << bit for bit in (12, 17, 20, 21, 22, 23, 24))
    _require(state["cpl"] == 0 and state["cs64"] and state["a20"] == 1 and
             state["no_npt"] and state["no_svm_guest"] and state["no_smm"] and
             state["cr0"] & 0x80000001 == 0x80000001 and state["cr4"] & 0x20 and
             state["efer"] & 0x500 == 0x500 and not state["cr4"] & unsupported,
             "mode_unsupported", "INCOMPLETE")
    return MappingProxyType(dict(state))


def _layout(raw):
    _require(type(raw) is bytes and len(raw) <= 65536, "layout_bound")
    try:
        result = capability.parse_flatview(raw.decode("ascii"))
    except (UnicodeError, capture.ProbeError) as error:
        raise C0DecodeError("DENY", "layout_invalid") from error
    _require(bool(result), "layout_no_ram")
    return result


class _Walker:
    """Finite current-memory model over supplied bytes, not a physical reader."""
    def __init__(self, state, tables, ranges):
        self.state = _mode(state)
        _require(type(tables) in _MAPPING, "table_mapping_type")
        self.tables = MappingProxyType(dict(tables))
        self.width_mask = (1 << self.state["phys_bits"]) - 1
        _require(not self.state["cr3"] & (U64 ^ self.width_mask), "cr3_reserved")
        self.root = self.state["cr3"] & self.width_mask & (U64 ^ 4095)
        _require(type(ranges) in (tuple, list) and 0 < len(ranges) <= 1024, "ram_ranges")
        normalized = []
        previous = 0
        for pair in ranges:
            _require(type(pair) in (tuple, list) and len(pair) == 2, "ram_range_shape")
            start, end = pair
            _integer(start, 0, self.width_mask); _integer(end, 1, self.width_mask + 1)
            _require(previous <= start < end, "ram_overlap")
            normalized.append((start, end)); previous = end
        self.ranges = tuple(normalized)
        self.levels, self.cache, self.lookups = {}, {}, []
        self.counts = _Counts()
        self._ram(self.root, 4096)

    def _ram(self, address, length):
        _integer(address, 0, self.width_mask); _integer(length, 1)
        _require(length <= self.width_mask + 1 - address, "ram_width")
        end, cursor = address + length, address
        first_boundary = None
        for low, high in self.ranges:
            if high <= cursor:
                continue
            _require(low <= cursor, "ram_hole")
            if first_boundary is None:
                first_boundary = high
            cursor = min(end, high)
            if cursor == end:
                return first_boundary
        raise C0DecodeError("DENY", "ram_backing")

    def _frame(self, address, level):
        _require(address % 4096 == 0, "frame_alignment")
        self._ram(address, 4096)
        _require(address not in self.levels or self.levels[address] == level, "frame_level")
        if address not in self.cache:
            self.counts.charge("frames", 1)
            self.lookups.append(address)
            raw = self._raw_frame(address, level)
            _require(type(raw) is bytes, "frame_type")
            _require(len(raw) == 4096, "frame_length", "INCOMPLETE")
            self.cache[address], self.levels[address] = raw, level
        return self.cache[address]

    def _raw_frame(self, address, level):
        _require(address in self.tables, "frame_missing", "INCOMPLETE")
        return self.tables[address]

    def translate(self, virtual, length):
        _span(virtual, length)
        output = []
        while length:
            self.counts.charge("translations", 1)
            walk = PageWalk(virtual, self.root, self.state["phys_bits"],
                            bool(self.state["efer"] & (1 << 11)))
            step = walk.next_frame
            while type(step) is NeedFrame:
                step = walk.accept(self._frame(step.physical, step.level))
            chunk = min(length, step.page_bytes - step.page_offset, 2048)
            boundary = self._ram(step.physical, chunk)
            chunk = min(chunk, boundary - step.physical)
            path = [{"frame": row.frame, "index": row.index, "entry": row.entry}
                    for row in step.path]
            output.append({"translation": {"virtual": virtual, "physical": step.physical,
                "length": chunk, "path": path, "writable": step.writable,
                "executable": step.executable, "user": step.user, "page_bytes": step.page_bytes},
                "cpl0_readable": True,
                "cpl0_writable": not bool(self.state["cr0"] & (1 << 16)) or step.writable})
            virtual += chunk; length -= chunk
        return output


@dataclass(frozen=True, slots=True)
class _MemoryRead:
    seq: int
    physical: int
    data: bytes


def _frame_bytes(address, first, recheck, reads):
    _integer(address); _require(address % 4096 == 0, "frame_alignment")
    _require(type(first) is bytes and type(recheck) is bytes, "frame_type")
    _require(len(first) == len(recheck) == 4096, "frame_length", "INCOMPLETE")
    _require(first == recheck, "frame_changed", "INCOMPLETE")
    _require(type(reads) in (tuple, list) and len(reads) == 4, "frame_read_identity")
    sequences = []
    for index, row in enumerate(reads):
        _require(type(row) is _MemoryRead, "frame_read_identity")
        _integer(row.seq, 1); sequences.append(row.seq)
        _integer(row.physical)
        offset = (index % 2) * 2048
        _require(row.physical == address + offset and type(row.data) is bytes and
                 row.data == first[offset:offset+2048], "frame_read_identity")
    _require(sequences == sorted(set(sequences)) and
             sequences[1] == sequences[0] + 1 and sequences[3] == sequences[2] + 1,
             "frame_read_identity")
    return first


def _crc32(data):
    _require(type(data) is bytes, "crc_input")
    return binascii.crc32(data) & 0xffffffff


def _efi(kind, data, address):
    _require(kind in ("system", "boot"), "efi_kind")
    size, signature, pointer_at = ((120, 0x5453595320494249, 96) if kind == "system"
                                   else (376, 0x56524553544f4f42, 56))
    _integer(address, 1); _require(address % 8 == 0, "efi_alignment"); _span(address, size)
    _require(type(data) is bytes, "efi_type")
    _require(len(data) == size, "efi_length", "INCOMPLETE")
    sig, revision, declared, crc, reserved = struct.unpack_from("<QIIII", data)
    _require((sig, revision, declared, reserved) == (signature, 0x20046, size, 0), "efi_header")
    _require(_crc32(data[:16] + bytes(4) + data[20:]) == crc, "efi_crc")
    pointer = struct.unpack_from("<Q", data, pointer_at)[0]
    _integer(pointer, 1)
    if kind == "system":
        _require(pointer % 8 == 0, "efi_pointer_alignment"); _span(pointer, 376)
    else:
        _span(pointer, 32)
    return pointer


def _loaded_pe(pinned, candidate_base, rip, headers, code):
    _integer(candidate_base); _integer(rip)
    try:
        pe = entry.parse_pe(pinned, 32)
        entry.loaded_extent(candidate_base, pe.image_size)
        _require(rip >= pe.entry_rva and rip - pe.entry_rva == candidate_base, "pe_candidate")
        for target, _ in pe.relocations:
            _require(target >= pe.header_size, "pe_header_relocation")
            overlap = max(target, pe.entry_rva) < min(target+8, pe.entry_rva+32)
            _require(not overlap or pe.entry_rva <= target and target+8 <= pe.entry_rva+32,
                     "pe_partial_relocation")
        expected = entry.expected_entry(pe, candidate_base)
    except entry.AdmissionError as error:
        raise C0DecodeError("DENY", "pe_" + str(error)) from error
    pe_offset = struct.unpack_from("<I", pinned, 60)[0]
    optional_offset = pe_offset + 24
    optional_size = struct.unpack_from("<H", pinned, pe_offset+20)[0]
    sections = struct.unpack_from("<H", pinned, pe_offset+6)[0]
    table = optional_offset + optional_size
    extents = {0: 64, pe_offset: 24, optional_offset: optional_size, table: sections*40}
    _require(type(headers) in _MAPPING and all(type(key) is int for key in headers), "pe_headers")
    _require(set(headers) <= set(extents), "pe_header_extent")
    _require(set(headers) == set(extents), "pe_header_missing", "INCOMPLETE")
    for offset, length in extents.items():
        expected_header = pinned[offset:offset+length]
        if offset == optional_offset:
            expected_header = (expected_header[:24] + candidate_base.to_bytes(8, "little") +
                               expected_header[32:])
        _require(type(headers[offset]) is bytes and headers[offset] == expected_header, "pe_header")
    _require(type(code) is bytes and len(code) == 32, "pe_entry_length", "INCOMPLETE")
    _require(code == expected, "pe_entry")
    return candidate_base


def _same(actual, expected):
    """JSON equality which never equates bool/float with an expected integer."""
    if type(expected) in _MAPPING:
        return (type(actual) in _MAPPING and set(actual) == set(expected) and
                all(_same(actual[key], value) for key, value in expected.items()))
    if type(expected) in (tuple, list):
        return (type(actual) in (tuple, list) and len(actual) == len(expected) and
                all(_same(a, b) for a, b in zip(actual, expected)))
    return type(actual) is type(expected) and actual == expected


def _hmp(raw, registers):
    _require(type(raw) is bytes and len(raw) <= 65536 and raw.isascii(), "hmp_shape")
    text = raw.decode("ascii"); lines = text.splitlines()
    _require([line for line in lines if line.startswith("CPU#")] == ["CPU#0"], "hmp_cpu")
    names = (*("R"+name for name in ("AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP")),
             *("R"+str(number) for number in range(8, 16)), "RIP", "RFL")
    fields = {name: (number, 8 if name == "RFL" else 16) for number, name in enumerate(names)}
    fields.update({"CR0": (27, 8), "CR2": (28, 16), "CR3": (29, 16),
                   "CR4": (30, 8), "EFER": (32, 16)})
    for name, (number, digits) in fields.items():
        spelling = name + (" " if name in ("R8", "R9") else "")
        matches = re.findall(rf"(?<![A-Za-z0-9_]){spelling}=([0-9a-f]{{{digits}}})(?=\s|$)", text)
        _require(len(matches) == 1 and int(matches[0], 16) == registers[number], "hmp_register")
    cs64 = False
    for name, number in (("CS", 18), ("SS", 19), ("DS", 20), ("ES", 21), ("FS", 22), ("GS", 23)):
        matches = [match for line in lines if (match := re.fullmatch(
            rf"{name} =([0-9a-f]{{4}}) [0-9a-f]{{16}} [0-9a-f]{{8}} ([0-9a-f]{{8}})(?: .*|)", line))]
        _require(len(matches) == 1 and int(matches[0][1], 16) == registers[number], "hmp_segment")
        if name == "CS":
            cs64 = bool(int(matches[0][2], 16) & (1 << 21))
    flags = {}
    for name in ("CPL", "SMM", "A20"):
        matches = re.findall(rf"\b{name}=([0-9]+)(?=\s|$)", text)
        _require(len(matches) == 1, "hmp_"+name.lower()+"_missing", "INCOMPLETE")
        value = int(matches[0]); _integer(value, 0, 3 if name == "CPL" else 1)
        flags[name.lower()] = value
    descriptors = {}
    for name in ("GDT", "IDT"):
        matches = [match for line in lines if (match := re.fullmatch(
            rf"{name}= +([0-9a-f]{{16}}) ([0-9a-f]{{8}})", line))]
        _require(len(matches) == 1, "hmp_descriptor")
        descriptors[name] = tuple(int(part, 16) for part in matches[0].groups())
    return _freeze({**flags, "cs64": cs64, "descriptors": descriptors})


SNAPSHOT_FIELDS = ("id", "phase", "rip", "loaded_base", "image_handle", "system_table",
    "boot_services", "get_memory_map", "stop_ref", "resume_seq", "breakpoint_seq",
    "registers_before_ref", "registers_after_ref", "hmp_before_ref", "hmp_after_ref",
    "layout_before_ref", "layout_after_ref", "tables", "objects", "translations",
    "observed_consistent", "atomic_snapshot", "device_quiescence_verified", "call_ref")


class _RecordedWalker(_Walker):
    """Resolve only the next admitted frame from this invocation's supplied bytes."""
    def __init__(self, state, ranges, owner):
        super().__init__(state, {}, ranges)
        self.owner = owner

    def _raw_frame(self, address, level):
        return self.owner.frame(address, level)


class _SnapshotReads:
    """Reconstruct named reads and their causal table ancestry from actual m rows."""
    def __init__(self, checkpoint, store, replay, state, ranges):
        _fields(checkpoint, SNAPSHOT_FIELDS, "snapshot_fields")
        _require(checkpoint["id"] == "C0" and checkpoint["phase"] == "firmware_active" and
                 checkpoint["atomic_snapshot"] is False and
                 checkpoint["device_quiescence_verified"] is False and checkpoint["call_ref"] is None,
                 "snapshot_identity")
        _require(type(checkpoint["observed_consistent"]) is bool, "snapshot_consistency_type")
        _require(checkpoint["observed_consistent"], "snapshot_changed", "INCOMPLETE")
        for name in ("rip", "loaded_base", "image_handle", "system_table", "boot_services", "get_memory_map"):
            _integer(checkpoint[name])
        for name, limit in (("tables", 32), ("objects", 32), ("translations", 128)):
            _require(type(checkpoint[name]) is list, "snapshot_array_type")
            _require(len(checkpoint[name]) <= limit, name+"_limit", "INCOMPLETE")
        self.checkpoint, self.store, self.replay = checkpoint, store, replay
        self.counts = _Counts()
        self.counts.charge("objects", len(checkpoint["objects"]))
        self.objects, self.used, self.first, self.rechecks = {}, set(), [], []
        self.frame_rows, self.object_results, self.all_translations = {}, {}, []
        # Whole-frame RAM validation happens before resolving any supplied frame bytes.
        self.walker = _Walker(state, {}, ranges)
        for row in checkpoint["tables"]:
            _fields(row, ("physical", "level", "first_ref", "recheck_ref", "read_sequences"), "table_fields")
            address = _integer(row["physical"]); _integer(row["level"], 1, 4)
            _require(address % 4096 == 0 and address not in self.frame_rows, "table_identity")
            self.walker._ram(address, 4096)
            sequences = row["read_sequences"]
            _require(type(sequences) is list and len(sequences) == 4, "frame_read_identity")
            self.frame_rows[address] = row
        self.walker = _RecordedWalker(state, ranges, self)
        for row in checkpoint["objects"]:
            _fields(row, ("role", "virtual", "length", "first_ref", "recheck_ref", "read_sequences"),
                    "object_fields")
            _require(row["role"] in ("pe_header", "entry_code", "system_table", "boot_services",
                                     "get_memory_map_code"), "object_role")
            _span(row["virtual"], row["length"]); _integer(row["length"], 1, 65536)
            key = (row["role"], row["virtual"], row["length"])
            _require(key not in self.objects, "object_duplicate")
            self.objects[key] = row

    def frame(self, address, level):
        _require(address in self.frame_rows, "frame_missing", "INCOMPLETE")
        row = self.frame_rows[address]
        _require(row["level"] == level, "table_declared_level")
        sequences = row["read_sequences"]
        first = self.store.get(row["first_ref"], 4096)
        recheck = self.store.get(row["recheck_ref"], 4096)
        _require(len(first) == len(recheck) == 4096, "frame_length", "INCOMPLETE")
        _require(first == recheck, "frame_changed", "INCOMPLETE")
        reads = [self.take(seq, address+(number % 2)*2048,
                           first[(number % 2)*2048:(number % 2+1)*2048])
                 for number, seq in enumerate(sequences)]
        result = _frame_bytes(address, first, recheck, reads)
        self.first.extend(sequences[:2]); self.rechecks.extend(sequences[2:])
        return result

    def take(self, sequence, address, data):
        _integer(sequence, 1)
        _require(sequence not in self.used, "read_sequence_reused")
        _require(sequence in self.replay["operations"], "read_sequence_missing", "INCOMPLETE")
        self.walker._ram(address, len(data))
        operation = self.replay["operations"][sequence]
        _require(operation["operation"] == "physical_read" and
                 operation["request_payload"] == f"m{address:x},{len(data):x}".encode(), "read_request_identity")
        _require(bytes.fromhex(operation["response_payload"].decode("ascii")) == data, "read_response_identity")
        self.used.add(sequence)
        return _MemoryRead(sequence, address, data)

    def object(self, role, virtual, length, executable=False):
        key = (role, virtual, length)
        _require(key not in self.object_results, "object_reused")
        _require(key in self.objects, "object_missing", "INCOMPLETE")
        row = self.objects[key]
        self.counts.charge("other_bytes", 2*length)
        translated = self.walker.translate(virtual, length)
        if executable:
            _require(all(part["translation"]["executable"] for part in translated), "code_not_executable")
        sequences = row["read_sequences"]
        _require(type(sequences) is list and len(sequences) == 2*len(translated), "object_read_count")
        _require(all(type(seq) is int for seq in sequences) and sequences == sorted(set(sequences)),
                 "object_read_sequence")
        first = self.store.get(row["first_ref"], length)
        recheck = self.store.get(row["recheck_ref"], length)
        _require(len(first) == len(recheck) == length, "object_length", "INCOMPLETE")
        _require(first == recheck, "object_changed", "INCOMPLETE")
        for pass_number in range(2):
            cursor = 0
            for number, result in enumerate(translated):
                part = result["translation"]
                sequence = sequences[pass_number*len(translated)+number]
                self.take(sequence, part["physical"], first[cursor:cursor+part["length"]])
                cursor += part["length"]
                for level, ancestor in zip(range(4, 0, -1), part["path"]):
                    parent = self.frame_rows[ancestor["frame"]]
                    _require(parent["level"] == level, "table_declared_level")
                    last_parent = self.replay["operations"][parent["read_sequences"][1]]
                    _require(last_parent["finished_ns"] <= self.replay["operations"][sequence]["started_ns"],
                             "table_after_object")
                for parent, child in zip(part["path"], part["path"][1:]):
                    last_parent = self.frame_rows[parent["frame"]]["read_sequences"][1]
                    first_child = self.frame_rows[child["frame"]]["read_sequences"][0]
                    _require(self.replay["operations"][last_parent]["finished_ns"] <=
                             self.replay["operations"][first_child]["started_ns"], "table_parent_order")
        half = len(translated)
        self.first.extend(sequences[:half]); self.rechecks.extend(sequences[half:])
        self.object_results[key] = (first, translated)
        return first

    def finish(self):
        _require(set(self.object_results) == set(self.objects), "object_unclaimed")
        _require(set(self.walker.cache) == set(self.frame_rows), "table_unclaimed")
        memory = {seq for seq, row in self.replay["operations"].items() if row["operation"] == "physical_read"}
        _require(self.used == memory, "read_unclaimed")
        _require(self.first and self.rechecks and max(self.first) < min(self.rechecks), "read_recheck_order")
        first_objects = [row["read_sequences"][0] for row in self.checkpoint["objects"]]
        _require(first_objects == sorted(first_objects), "object_request_order")
        for row in self.checkpoint["objects"]:
            key = (row["role"], row["virtual"], row["length"])
            self.all_translations.extend(self.object_results[key][1])
        _require(_same(self.checkpoint["translations"], [part["translation"] for part in self.all_translations]),
                 "translation_identity")
        return self.all_translations


def _decode_objects(checkpoint, store, replay, state, ranges, pinned, candidate):
    reads = _SnapshotReads(checkpoint, store, replay, state, ranges)
    pe = entry.parse_pe(pinned, 32)
    base, rip = candidate["loaded_base"], replay["before_registers"][16]
    _require(checkpoint["rip"] == rip and checkpoint["loaded_base"] == base and
             checkpoint["image_handle"] == replay["before_registers"][2] and
             checkpoint["system_table"] == replay["before_registers"][3], "snapshot_register_identity")
    _require(rip == candidate["entry_address"], "snapshot_candidate")
    entry.loaded_extent(base, pe.image_size)
    pe_offset = struct.unpack_from("<I", pinned, 60)[0]
    optional_size = struct.unpack_from("<H", pinned, pe_offset+20)[0]
    section_count = struct.unpack_from("<H", pinned, pe_offset+6)[0]
    extents = ((0, 64), (pe_offset, 24), (pe_offset+24, optional_size),
               (pe_offset+24+optional_size, section_count*40))
    headers = {offset: reads.object("pe_header", base+offset, length) for offset, length in extents}
    code = reads.object("entry_code", rip, 32, executable=True)
    _loaded_pe(pinned, base, rip, headers, code)
    system = checkpoint["system_table"]
    _integer(system, 1); _require(system % 8 == 0, "efi_alignment"); _span(system, 120)
    boot = _efi("system", reads.object("system_table", system, 120), system)
    _require(boot == checkpoint["boot_services"], "boot_pointer_identity")
    system_reads = reads.objects[("system_table", system, 120)]["read_sequences"]
    boot_row = reads.objects.get(("boot_services", boot, 376))
    _require(boot_row is not None, "object_missing", "INCOMPLETE")
    _require(type(boot_row["read_sequences"]) is list and boot_row["read_sequences"] and
             type(boot_row["read_sequences"][0]) is int and
             max(system_reads[:len(system_reads)//2]) < boot_row["read_sequences"][0], "efi_pointer_read_order")
    gmm = _efi("boot", reads.object("boot_services", boot, 376), boot)
    _require(gmm == checkpoint["get_memory_map"], "gmm_pointer_identity")
    gmm_row = reads.objects.get(("get_memory_map_code", gmm, 32))
    _require(gmm_row is not None, "object_missing", "INCOMPLETE")
    boot_reads = boot_row["read_sequences"]
    _require(type(gmm_row["read_sequences"]) is list and gmm_row["read_sequences"] and
             type(gmm_row["read_sequences"][0]) is int and
             max(boot_reads[:len(boot_reads)//2]) < gmm_row["read_sequences"][0], "efi_pointer_read_order")
    reads.object("get_memory_map_code", gmm, 32, executable=True)
    return {"loaded_base": base, "entry_address": rip, "image_handle": checkpoint["image_handle"],
            "system_table": system, "boot_services": boot, "get_memory_map": gmm}, reads.finish()


def _profile_binding(report, store):
    """Recompute the existing prior-hint admission, never a fresh address source."""
    profile = _json(store.get(report["profile_ref"], 65536), 65536)
    _fields(profile, ("schema_version", "kind", "invocation_profile", "source_commit",
        "assembled_patch_sha256", "diagnostic_image_name", "inputs", "provenance"), "profile_fields")
    _integer(profile["schema_version"], 1, 1)
    _require(profile["kind"] == "boot_profile_probe_inputs_v0", "profile_identity")
    machine = capture.admission_machine(profile["invocation_profile"])
    _fields(profile["inputs"], capture.INPUT_LIMITS, "profile_inputs")
    _fields(profile["provenance"], capture.PROVENANCE_KEYS, "profile_provenance")
    for name, limit in capture.INPUT_LIMITS.items():
        ref = _ref(profile["inputs"][name], limit)
        _require(ref["path"] == ("7z.so" if name == "seven_zip_module" else name), "profile_input_path")
        store.get(ref, limit)
    for ref in profile["provenance"].values():
        store.get(ref, 32 << 20)
    mapping = _json(store.get(report["profile_mapping_ref"], 65536), 65536)
    _fields(mapping, ("admission_profile_sha256", "claims", "inputs", "opaque_expanded_cpu_ref",
        "opaque_invocation_ref", "probe_profile_ref", "probe_profile_sha256", "probe_report_ref",
        "scope", "whole_unmodified_diagnostic_ref"), "profile_mapping_fields")
    _require(_same(mapping["claims"], {name: False for name in entry.CLAIM_NAMES}) and
             mapping["scope"] == "field-by-field mapping of the actual prior probe to existing admission subset; no fresh C0 or runtime qualification",
             "profile_mapping_claims")
    _require(store.get(mapping["probe_profile_ref"], 65536) == store.get(report["profile_ref"], 65536)
             and mapping["probe_profile_sha256"] == entry.profile_digest(profile), "profile_mapping_identity")
    names = set(entry.ARTIFACT_LIMITS) - {"expanded_cpu", "invocation"}
    _fields(mapping["inputs"], names, "profile_mapping_inputs")
    artifacts = {}
    for name in sorted(names):
        row = mapping["inputs"][name]
        _fields(row, ("admission_ref", "probe_ref", "length_and_sha256_equal"), "profile_mapping_row")
        _require(_same(row["probe_ref"], profile["inputs"][name]) and
                 row["length_and_sha256_equal"] is True, "profile_mapping_row_identity")
        a = store.get(row["admission_ref"], entry.ARTIFACT_LIMITS[name])
        b = store.get(row["probe_ref"], entry.ARTIFACT_LIMITS[name])
        _require(a == b, "profile_mapping_input_bytes")
        artifacts[name] = row["admission_ref"]
    for name in ("expanded_cpu", "invocation"):
        artifacts[name] = mapping["opaque_"+name+"_ref"]
        store.get(artifacts[name], entry.ARTIFACT_LIMITS[name])
    admission = _json(store.get(report["prior_admission_ref"], 65536), 65536)
    _fields(admission, (*entry.report("ADMIT", "prior_candidate_inputs_checked"), "profile_sha256", "pe", "candidate"),
            "admission_fields")
    _require(all(_same(admission[key], value) for key, value in entry.report(
        "ADMIT", "prior_candidate_inputs_checked").items()), "admission_status_or_claims")
    candidate = admission["candidate"]
    _fields(candidate, ("scope", "loaded_base", "entry_address", "diagnostic_line", "expected_entry_hex",
                       "prior_run_id", "diagnostic_ref"), "candidate_fields")
    admission_profile = {name: profile[name] for name in
                         ("source_commit", "assembled_patch_sha256", "diagnostic_image_name")}
    admission_profile.update(machine=machine, accelerator="tcg", cpu="qemu64", vcpus=1,
                             ram_bytes=512 << 20, artifacts=artifacts)
    packet = {"schema_version": 1, "kind": "boot_entry_inputs_v0", "entry_length": 32,
        "profile": admission_profile, "prior_hint": {"prior_run_id": candidate["prior_run_id"],
        "profile_sha256": mapping["admission_profile_sha256"],
        "diagnostic_ref": mapping["whole_unmodified_diagnostic_ref"]}}
    entry.validate_packet(packet)
    _require(admission["profile_sha256"] == entry.profile_digest(admission_profile) ==
             mapping["admission_profile_sha256"] and
             _same(candidate["diagnostic_ref"], mapping["whole_unmodified_diagnostic_ref"]), "admission_profile")
    pinned = store.get(profile["inputs"]["efi"], entry.EFI_LIMIT)
    pe = entry.parse_pe(pinned, 32)
    diagnostic = store.get(candidate["diagnostic_ref"], 65536)
    parsed = entry.parse_diagnostic(diagnostic, profile["diagnostic_image_name"])
    expected = {**entry.diagnostic_candidate(parsed, pe), "prior_run_id": candidate["prior_run_id"],
                "diagnostic_ref": dict(candidate["diagnostic_ref"])}
    _require(_same(candidate, expected), "candidate_recomputed")
    _require(_same(admission["pe"], {name: getattr(pe, name) for name in
        ("image_base", "image_size", "header_size", "entry_rva", "entry_file_offset", "entry_length")}),
        "admission_pe")
    # The older diagnostic probe is an identity-bound prior hint only. Its
    # dynamic observation records are not reclassified as C0 or runtime proof.
    probe = _json(store.get(mapping["probe_report_ref"], REPORT_LIMIT))
    _fields(probe, ("argv", "async_events", "candidate", "capture_complete", "checkpoints", "claims",
        "cleanup", "configured_cpu_expansion", "cpu_expansion_origin", "esp_validation", "final_vars",
        "finished_utc", "initial_vars", "input_pins_unchanged_after_run", "kind", "late_qmp_records",
        "lifecycle_deadline_met", "message_count", "observation_scope", "observer", "operations",
        "owned_pid", "profile", "profile_preconditions_met", "profile_sha256", "quit_result", "raw_files",
        "reason", "reset_cpus", "reset_ram_layout_text", "reset_register_text", "retained_stream_bytes",
        "schema_version", "started_utc", "status", "stream_errors", "streams_complete_to_eof",
        "transport_eof_observations"), "prior_probe_fields")
    _require(type(probe) is dict and probe.get("schema_version") == 1 and
             type(probe.get("schema_version")) is int and probe.get("kind") == "boot_profile_probe_v0" and
             probe.get("profile_sha256") == entry.profile_digest(profile) and
             _same(probe.get("profile"), profile) and
             _same(probe.get("candidate"), entry.diagnostic_candidate(parsed, pe)) and
             probe.get("status") == "CANDIDATE_RETAINED" and
             _same(probe.get("claims"), {name: False for name in entry.CLAIM_NAMES}) and
             probe.get("capture_complete") is False and probe.get("profile_preconditions_met") is False,
             "prior_probe_binding")
    capability.validate_invocation_argv(probe["argv"], profile["invocation_profile"])
    files = probe.get("raw_files")
    _require(type(files) is list and len(files) <= 16, "prior_probe_raw_files")
    diagnostic_rows = [row for row in files if type(row) is dict and row.get("path") == "debug.bin"]
    _require(len(diagnostic_rows) == 1, "prior_diagnostic_missing", "INCOMPLETE")
    old = _ref(diagnostic_rows[0], 65536)
    parent = mapping["probe_report_ref"]["path"].rsplit("/", 1)
    expected_path = (parent[0]+"/" if len(parent) == 2 else "")+old["path"]
    _require(candidate["diagnostic_ref"] == {**old, "path": expected_path}, "prior_diagnostic_identity")
    return profile, pinned, expected


def _slice_bytes(store, reference):
    _fields(reference, ("blob", "offset", "length"), "wire_slice_fields")
    raw = store.get(reference["blob"], LIMITS["retained_bytes"])
    offset, length = _integer(reference["offset"]), _integer(reference["length"], 1, 65536)
    _require(offset <= len(raw) and length <= len(raw)-offset, "wire_slice_bounds")
    return raw[offset:offset+length]


def _qmp_reply(store, operation):
    value = _json(_slice_bytes(store, operation["response"]), 65536)
    _require(type(value) is dict and "return" in value, "qmp_response_missing", "INCOMPLETE")
    return value["return"]


def _operations_binding(report, control, store):
    rows = report["operations"]
    _require(type(rows) is list and len(rows) <= 512, "operations_limit", "INCOMPLETE")
    _require(len(rows) == len(control["operations"]), "operations_inventory")
    for number, (row, actual) in enumerate(zip(rows, control["operations"]), 1):
        _fields(row, ("seq", "protocol", "operation", "request_ref", "response_ref",
                      "started_ns", "finished_ns", "result"), "operation_fields")
        _integer(row["seq"], number, number)
        for name in ("seq", "protocol", "operation", "started_ns", "finished_ns", "result"):
            _require(_same(row[name], actual[name]), "operation_index_identity")
        _require(store.get(row["request_ref"], 65536) == _slice_bytes(store, actual["request"]),
                 "operation_request_bytes")
        if actual["response"] is None:
            _require(row["response_ref"] is None, "operation_response_identity")
        else:
            _require(store.get(row["response_ref"], 65536) == _slice_bytes(store, actual["response"]),
                     "operation_response_bytes")


def _termination(end):
    _fields(end, ("status", "reason", "reaped", "returncode", "actions", "grace", "streams"),
            "termination_fields")
    _require(end["status"] in ("PASS", "INCOMPLETE", "DENY") and
             type(end["reason"]) is str and re.fullmatch(r"[a-z0-9_]{1,96}", end["reason"]),
             "termination_status")
    _require(type(end["reaped"]) is bool and
             (end["returncode"] is None or type(end["returncode"]) is int and
              -(1 << 31) <= end["returncode"] < 1 << 31), "termination_wait_type")
    _require(type(end["actions"]) is list and len(end["actions"]) <= 8 and
             all(type(item) is str and 0 < len(item) <= 96 for item in end["actions"]) and
             end["grace"] in ("not_attempted", "exited", "timeout", "error"), "termination_actions")
    _require(type(end["streams"]) is list and len(end["streams"]) == 6, "termination_streams")
    for row, name in zip(end["streams"], ("qmp", "rsp", "serial", "debug", "stdout", "stderr")):
        _fields(row, ("name", "eof", "error"), "termination_stream_fields")
        _require(row["name"] == name and type(row["eof"]) is bool, "termination_stream_identity")
        if row["error"] is not None:
            _fields(row["error"], ("operation", "errno"), "termination_error_fields")
            _require(row["error"]["operation"] in ("read", "write", "close"), "termination_error_operation")
            _integer(row["error"]["errno"], 1, 4095)
    _require(end["status"] != "DENY", "termination_denied")
    _require(end["status"] == "PASS" and end["reaped"] and type(end["returncode"]) is int and
             end["returncode"] == 0 and not end["actions"] and end["grace"] == "exited" and
             all(row["eof"] and row["error"] is None for row in end["streams"]),
             "termination_incomplete", "INCOMPLETE")


def _witness_binding(origin, report, store, prerequisites):
    import run0_host_cpu_witness as witness

    _require(prerequisites is not None, "host_witness_missing", "INCOMPLETE")
    _require(type(prerequisites) is witness.ValidatedHostState, "host_witness_type")
    supplied = witness.export_validated_host_state(prerequisites)
    _require(supplied["origin"] == origin and supplied["final_status"] == "PASS", "host_witness_origin")
    # Revalidation ties the opaque value to the bytes supplied for this invocation,
    # rather than accepting a previously checked reference whose bytes are absent.
    actual = witness.export_validated_host_state(witness.validate_report(supplied["report_ref"], store.values.copy()))
    _require(_same(actual["binding"], supplied["binding"]) and _same(actual["state"], supplied["state"]),
             "host_witness_changed")
    host = _json(store.get(actual["report_ref"], REPORT_LIMIT))
    binding, state = actual["binding"], actual["state"]
    _require(binding["context"] == "c0" and binding["stop_id"] == "C0" and
             binding["run_id"] == report["run_id"] and binding["rsp_thread"] == "01" and
             type(binding["cpu_index"]) is int and binding["cpu_index"] == 0, "host_stop_binding")
    _require(state["observed_consistent"] is True and state["cpl"] == 0 and state["cs64"] is True and
             state["lma"] is True and state["no_npt"] is True and
             state["no_svm_guest"] is True and state["no_smm"] is True,
             "host_mode_unsupported", "INCOMPLETE")
    for our, theirs in (("profile_ref", "profile_ref"), ("observer_ref", "observer_ref"),
                       ("source_dossier_ref", "source_ref")):
        _require(_same(report[our], host[theirs]), "host_source_binding")
    plan = _json(store.get(host["plan_ref"], REPORT_LIMIT))
    _require(_same(_json(store.get(report["argv_ref"], 65536), 65536), plan["argv"]), "host_argv_binding")
    bound_profile = _json(store.get(host["profile_ref"], 65536), 65536)
    control, tid = witness.validate_control_index(host["control_ref"], store.values.copy(), binding,
        invocation_profile=bound_profile.get("invocation_profile", capture.INVOCATION_PROFILE))
    _require(tid == binding["qmp_thread_id"], "host_tid_binding")
    return host, binding, state, control, actual["report_ref"]


def _snapshot_binding(checkpoint, store, replay, host_state, binding, control, invocation_profile):
    _require(checkpoint is not None, "checkpoint_missing", "INCOMPLETE")
    _fields(checkpoint, SNAPSHOT_FIELDS, "snapshot_fields")
    for name in ("resume_seq", "breakpoint_seq"):
        _integer(checkpoint[name], 1)
        _require(checkpoint[name] == binding[name] == replay[name], "snapshot_stop_sequence")
    _require(_same(checkpoint["stop_ref"], binding["stop_ref"]) and
             store.get(checkpoint["stop_ref"], 8192) == _slice_bytes(store, replay["stop_event"]["wire"]),
             "snapshot_stop_ref")
    for phase in ("before", "after"):
        index = _json(store.get(checkpoint["registers_"+phase+"_ref"], 65536), 65536)
        _fields(index, ("schema_version", "operations"), "register_index_fields")
        _integer(index["schema_version"], 1, 1)
        _require(_same(index["operations"], replay[phase+"_sequences"]), "register_index_identity")
    memory = [row for row in control["operations"] if row["operation"] == "physical_read"]
    first, last = memory[0]["seq"], memory[-1]["seq"]
    hmp_before = control["operations"][control["before"]["hmp_seq"]-1]
    after = [row for row in control["operations"] if row["operation"] == "hmp_registers" and row["seq"] > last]
    layouts = [row for row in control["operations"] if row["operation"] == "hmp_flatview"]
    _require(len(after) == 1 and len(layouts) == 2 and
             layouts[0]["seq"] < first <= last < layouts[1]["seq"], "snapshot_brackets")
    after_register = control["operations"][replay["after_sequences"][-1]-1]
    host_after = control["operations"][control["after"]["hmp_seq"]-1]
    _require(host_after["finished_ns"] <= layouts[0]["started_ns"] and
             after_register["finished_ns"] <= after[0]["started_ns"] and
             after[0]["finished_ns"] <= layouts[1]["started_ns"], "snapshot_bracket_order")
    _require(layouts[1]["finished_ns"]-replay["stop_event"]["received_ns"] <= 60_000_000_000,
             "snapshot_stop_deadline", "INCOMPLETE")
    parsed_hmp, parsed_layout, hmp_raw, layout_raw = [], [], [], []
    for phase, hmp_op, layout_op in (("before", hmp_before, layouts[0]), ("after", after[0], layouts[1])):
        hmp = store.get(checkpoint["hmp_"+phase+"_ref"], 65536)
        layout = store.get(checkpoint["layout_"+phase+"_ref"], 65536)
        expected_hmp, expected_layout = _qmp_reply(store, hmp_op), _qmp_reply(store, layout_op)
        _require(type(expected_hmp) is str and type(expected_layout) is str and
                 hmp == expected_hmp.encode("ascii") and layout == expected_layout.encode("ascii"),
                 "snapshot_text_identity")
        parsed_hmp.append(_hmp(hmp, replay[phase+"_registers"]))
        parsed_layout.append(_layout(layout))
        if invocation_profile == capture.VAPIC_OFF_INVOCATION_PROFILE:
            capability.validate_profile_layout(layout.decode("ascii"), invocation_profile)
        hmp_raw.append(hmp)
        layout_raw.append(layout)
    _require(parsed_hmp[0] == parsed_hmp[1] and parsed_layout[0] == parsed_layout[1] and
             hmp_raw[0] == hmp_raw[1] and layout_raw[0] == layout_raw[1], "snapshot_bracket_changed", "INCOMPLETE")
    before = parsed_hmp[0]
    _require(before["cpl"] == host_state["cpl"] and before["cs64"] == host_state["cs64"] and
             before["smm"] == 0, "snapshot_host_mode")
    width_op = control["operations"][control["before"]["phys_bits_seq"]-1]
    width = _qmp_reply(store, width_op)
    registers = replay["before_registers"]
    state = _mode({"phys_bits": width, "cr0": registers[27], "cr3": registers[29],
        "cr4": registers[30], "efer": registers[32], "cpl": before["cpl"], "cs64": before["cs64"],
        "a20": before["a20"], "no_npt": host_state["no_npt"],
        "no_svm_guest": host_state["no_svm_guest"], "no_smm": host_state["no_smm"]})
    return state, parsed_layout[0]


def _retained_accounting(report_ref, report, host_ref, host, store, control, profile):
    """Closed current-output closure; separate physical copies are charged again."""
    refs = {}

    def collect(value):
        if type(value) in _MAPPING:
            if set(value) == {"path", "sha256", "length"}:
                reference = _ref(value, LIMITS["retained_bytes"])
                _require(reference["path"].split("/", 1)[0] != "prior-cap1", "output_namespace")
                _require(reference["path"] not in refs or refs[reference["path"]] == reference,
                         "output_identity")
                refs[reference["path"]] = reference
            else:
                for item in value.values():
                    collect(item)
        elif type(value) in (list, tuple):
            for item in value:
                collect(item)

    collect(report_ref)
    # Prior admission/mapping/capability are bounded immutable inputs, unlike
    # this run's reports, raw files, indexes and copied profile/source records.
    for key, value in report.items():
        if key not in ("prior_admission_ref", "profile_mapping_ref", "capability_ref"):
            collect(value)
    collect(host_ref); collect(host)
    for key in ("plan_ref", "metadata_before_ref", "metadata_after_ref", "peer_ref", "sigchld_ref",
                "process_ref", "reads_ref", "control_ref"):
        record = _json(store.get(host[key], REPORT_LIMIT))
        collect(record)
        if key == "process_ref":
            collect(_json(store.get(record["lifecycle_ref"], REPORT_LIMIT)))
    streams = _json(store.get(host["termination"]["streams_ref"], REPORT_LIMIT))
    collect(streams)
    canonical_streams = {"qmp", "rsp", "serial", "debug", "qemu_stdout", "qemu_stderr"}
    selected_streams = [row for row in streams["rows"] if row["name"] in canonical_streams]
    _require({row["name"] for row in selected_streams} == canonical_streams,
             "current_stream_outcome_missing", "INCOMPLETE")
    for row in selected_streams:
        _require(row["raw_ref"] in report["raw_refs"], "raw_stream_reference")
        _require(row["eof"] is True and row["error"] is None, "current_stream_incomplete", "INCOMPLETE")
    for name in ("raw_qmp_in_ref", "raw_qmp_out_ref", "raw_rsp_in_ref", "raw_rsp_out_ref"):
        _require(control[name] in report["raw_refs"], "raw_stream_reference")
    vars_rows = [ref for ref in report["raw_refs"] if ref["path"] == "vars.fd"]
    _require(len(vars_rows) == 1, "private_vars_missing", "INCOMPLETE")
    _require(vars_rows[0]["length"] == profile["inputs"]["initial_vars"]["length"], "private_vars_length")
    counter = _Counts()
    for reference in refs.values():
        counter.charge("retained_bytes", reference["length"])
    return tuple(refs.values())


def _capability_binding(report, store, profile):
    reference = _ref(report["capability_ref"], REPORT_LIMIT)
    _require(reference["path"] == "prior-cap1/report.json", "capability_namespace")
    previous = _json(store.get(reference, REPORT_LIMIT))
    capability.validate_report(previous)
    _termination(previous["termination"])

    def prior_blob(reference, limit):
        # CAP1 validates all nested names as flat paths. Prefix only the lookup,
        # preserving the original report bytes and keeping current files separate.
        return store.get({**reference, "path": "prior-cap1/" + reference["path"]}, limit)

    _require(_same(_json(prior_blob(previous["profile_ref"], 65536), 65536), profile) and
             prior_blob(previous["source_dossier_ref"], 65536) ==
             store.get(report["source_dossier_ref"], 65536), "capability_profile_binding")
    prior_blob(previous["observer_ref"], 65536)
    argv = _json(prior_blob(previous["argv_ref"], 65536), 65536)
    capability.validate_invocation_argv(argv, profile["invocation_profile"])
    for ref in previous["raw_refs"]:
        prior_blob(ref, LIMITS["retained_bytes"])
    for key in capability.OBS_REFS:
        prior_blob(previous["observations"][key], 65536)
    if profile["invocation_profile"] == capture.VAPIC_OFF_INVOCATION_PROFILE:
        layout = prior_blob(previous["observations"]["layout_ref"], 65536)
        _require(layout.isascii(), "capability_layout_encoding")
        capability.validate_profile_layout(layout.decode("ascii"), profile["invocation_profile"])
    for row in previous["operations"]:
        prior_blob(row["request_ref"], 65536)
        if row["response_ref"] is not None:
            prior_blob(row["response_ref"], 65536)


def decode_c0(origin, report_ref, blobs, prerequisites):
    """Decode only a structurally bound retained artifact; never acquire bytes."""
    _require(type(origin) is str and origin in ("synthetic_fixture", "retained_runtime"), "origin")
    _require(type(report_ref) is dict and all(type(key) is str for key in report_ref), "report_ref_type")
    report_ref = _ref(report_ref, REPORT_LIMIT)
    result = {"schema_version": 1, "kind": "run0_c0_decode_v0", "origin": origin,
              "report_ref": report_ref, "host_cpu_witness_ref": None,
              "status": "INCOMPLETE", "reason": "evidence_not_finished",
              "observed_consistent": False, "loaded_identity": None, "translations": [],
              "claims": dict(FALSE_CLAIMS), "fresh_c0_verified": False,
              "atomic_snapshot": False, "device_quiescence_verified": False,
              "remaining_checkpoints": ["C1", "C2"]}
    try:
        store = _Blobs(blobs)
        report = _json(store.get(report_ref, REPORT_LIMIT))
        _fields(report, ("schema_version", "kind", "run_id", "profile_ref", "observer_ref",
            "source_dossier_ref", "capability_ref", "prior_admission_ref", "profile_mapping_ref",
            "argv_ref", "raw_refs", "operations", "checkpoint", "termination", "claims",
            "fresh_c0_verified", "remaining_checkpoints"), "c0_report_fields")
        _integer(report["schema_version"], 1, 1)
        _require(report["kind"] == "run0_c0_inspection_subset_v0" and type(report["run_id"]) is str and
                 re.fullmatch(r"[a-z0-9-]{1,64}", report["run_id"]), "c0_report_identity")
        _require(_same(report["claims"], FALSE_CLAIMS) and
                 type(report["fresh_c0_verified"]) is bool and
                 _same(report["remaining_checkpoints"], ["C1", "C2"]), "c0_report_claims")
        _require(type(report["raw_refs"]) is list and len(report["raw_refs"]) <= 16, "raw_refs_limit")
        for reference in report["raw_refs"]:
            _ref(reference, LIMITS["retained_bytes"])
        _require(len({ref["path"] for ref in report["raw_refs"]}) == len(report["raw_refs"]), "raw_refs_duplicate")
        host, binding, host_state, control, host_ref = _witness_binding(origin, report, store, prerequisites)
        result["host_cpu_witness_ref"] = host_ref
        profile, pinned, candidate = _profile_binding(report, store)
        _require(entry.profile_digest(profile) == binding["profile_sha256"], "c0_profile_binding")
        abi = _json(store.get(host["abi_ref"], REPORT_LIMIT))
        _require(store.get(abi["qemu_ref"], 64 << 20) ==
                 store.get(profile["inputs"]["qemu"], capture.INPUT_LIMITS["qemu"]), "qemu_executable_binding")
        _capability_binding(report, store, profile)
        _operations_binding(report, control, store)
        replay = validate_c0_rsp(control, store.values.copy())
        state, ranges = _snapshot_binding(report["checkpoint"], store, replay, host_state, binding,
                                          control, profile["invocation_profile"])
        _termination(report["termination"])
        retained_refs = _retained_accounting(report_ref, report, host_ref, host, store, control, profile)
        loaded, translations = _decode_objects(report["checkpoint"], store, replay, state, ranges, pinned, candidate)
        for reference in retained_refs:
            store.get(reference, LIMITS["retained_bytes"])
        result.update(status="PASS", reason="retained_c0_decoded", observed_consistent=True,
                      loaded_identity=loaded, translations=translations)
    except C0DecodeError as error:
        result.update(status=error.status, reason=error.reason)
    except capture.ProbeError as error:
        result.update(status=error.status, reason=error.reason)
    except entry.UnavailableInput:
        result.update(status="INCOMPLETE", reason="prior_diagnostic_missing")
    except entry.AdmissionError:
        result.update(status="DENY", reason="prior_admission_invalid")
    return result
