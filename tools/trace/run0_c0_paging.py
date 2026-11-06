"""Bounded four-level C0 page walks over exact caller-supplied frame bytes."""

from dataclasses import dataclass
import struct


U64 = (1 << 64) - 1


class C0DecodeError(Exception):
    """Stable first failure; the exception's diagnostic fields are immutable."""
    def __init__(self, status, reason):
        super().__init__(reason)
        self._status, self._reason = status, reason

    @property
    def status(self):
        return self._status

    @property
    def reason(self):
        return self._reason

    def __setattr__(self, name, value):
        if name in ("status", "reason", "_status", "_reason") and hasattr(self, name):
            raise AttributeError("immutable decoder failure")
        super().__setattr__(name, value)


def require(condition, reason, status="DENY"):
    if not condition:
        raise C0DecodeError(status, reason)


def integer(value, low=0, high=U64):
    require(type(value) is int and low <= value <= high, "integer_range")
    return value


def canonical_span(start, length):
    integer(start)
    integer(length, 1)
    require(length - 1 <= U64 - start, "span_overflow")
    last = start + length - 1
    require(last < (1 << 47) or start >= (1 << 64) - (1 << 47), "span_noncanonical")
    return start, last + 1


@dataclass(frozen=True, slots=True)
class NeedFrame:
    physical: int
    level: int
    index: int


@dataclass(frozen=True, slots=True)
class PageEntry:
    frame: int
    index: int
    entry: int


@dataclass(frozen=True, slots=True)
class PageTranslation:
    physical: int
    page_bytes: int
    page_offset: int
    path: tuple[PageEntry, ...]
    writable: bool
    executable: bool
    user: bool


class PageWalk:
    """One translation. Demands carry addresses and require separate RAM admission."""

    __slots__ = ("_virtual", "_width_mask", "_nxe", "_next_frame", "_path",
                 "_writable", "_executable", "_user")

    def __init__(self, virtual, root, phys_bits, nxe):
        canonical_span(virtual, 1)
        integer(phys_bits, 32, 52)
        self._width_mask = (1 << phys_bits) - 1
        integer(root, 0, self._width_mask)
        require(root % 4096 == 0, "frame_alignment")
        require(type(nxe) is bool, "nxe_type")
        self._virtual, self._nxe = virtual, nxe
        self._next_frame = self._need(root, 4)
        self._path = ()
        self._writable = self._executable = self._user = True

    def _need(self, physical, level):
        shift = 12 + 9 * (level - 1)
        return NeedFrame(physical, level, (self._virtual >> shift) & 511)

    @property
    def next_frame(self):
        return self._next_frame

    def accept(self, frame):
        """Consume exactly one complete frame after the owner admits and supplies it."""
        need = self._next_frame
        require(need is not None, "walk_complete")
        require(type(frame) is bytes, "frame_type")
        require(len(frame) == 4096, "frame_length", "INCOMPLETE")
        value = struct.unpack_from("<Q", frame, need.index * 8)[0]
        require(value & 1, "unmapped", "INCOMPLETE")
        reserved = ((1 << 52) - 1) & (U64 ^ self._width_mask)
        if not self._nxe:
            reserved |= 1 << 63
        if need.level == 4:
            reserved |= 0x80
        if need.level == 2 and value & 0x80:
            reserved |= 0x1fe000
        require(not value & reserved, "entry_reserved")
        require(not (need.level == 3 and value & 0x80), "one_gib_unsupported", "INCOMPLETE")

        self._path += (PageEntry(need.physical, need.index, value),)
        self._writable = self._writable and bool(value & 2)
        self._user = self._user and bool(value & 4)
        self._executable = self._executable and not bool(value & (1 << 63))
        if need.level == 1 or need.level == 2 and value & 0x80:
            page_bytes = 4096 if need.level == 1 else 1 << 21
            offset = self._virtual & (page_bytes - 1)
            physical = (value & self._width_mask & (U64 ^ (page_bytes - 1))) + offset
            self._next_frame = None
            return PageTranslation(physical, page_bytes, offset, self._path,
                                   self._writable, self._executable, self._user)
        physical = value & self._width_mask & (U64 ^ 4095)
        self._next_frame = self._need(physical, need.level - 1)
        return self._next_frame
