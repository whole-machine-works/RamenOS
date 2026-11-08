"""Closed same-call parent wire. Constructor setup has no endpoint effects.

Fixed Root methods authenticate the held native graph before all IO. Private
socket controls patch that guard only; no production fixture/origin switch or
acquiring session callback exists here. Old C0 wire/source remains unchanged.
"""
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass,replace
import importlib
import json
import os
import selectors
import socket
import time

from boot_profile_capture import ProbeError,decode_frame,deny,incomplete,MAX_FRAME
import run0_rsp as rsp
from run0_call_budget import ParentAccounting
from run0_call_owner import ParentDeadlines,TransitionAdmission,ClosedEpochReceipt
from run0_call_read import LiveWirePosition,_HeldReadAttempt,_HeldReadOperation,PendingReadRetention

SECOND=1_000_000_000
RESPONSE_NS=5*SECOND
MAX_OPERATIONS=1024
MAX_EVENTS=128
MAX_QMP_FRAMES=128
MAX_QMP_BYTES=1<<20
MAX_RSP_FRAMES=2051
MAX_RSP_ACKS=1024
MAX_RSP_SEGMENTS=2048
READ_CHUNK=65536
ROW_CREDIT=2048
FRAME_CREDIT=256
STREAMS=('rsp','serial','debug','qemu_stdout','qemu_stderr')
_COMMANDS=('qmp_capabilities','query-commands','query-status')
_REQUIRED_COMMANDS=(*_COMMANDS,'query-cpus-fast','qom-get','human-monitor-command','quit')
_ROOT_METHODS=frozenset(('_require_wire_bootstrap','_require_wire_stop','_require_wire_binding',
 '_require_wire_after','_require_wire_transition','_issue_wire_transition','_require_wire_resume',
 '_require_wire_termination','_require_wire_failure_drain','_prepare_wire_read','_commit_wire_read',
 '_recheck_wire_read','_seal_wire_read','_abort_wire_epoch'))


def _root_guard(wire,name,*args,**kwargs):
    """Closed dispatcher, never an externally supplied callback or method name."""
    deny(name in _ROOT_METHODS,'call_root_method')
    try:
        root=importlib.import_module('run0_call_capture')
        registration=wire._registration
        incomplete(type(registration) is root.ClosedOwnedCallRegistration
            and type(registration._owner) is root._OwnedCallRuntime
            and root._issued_call_registration(registration,wire),
            'call_runtime_registration_pending')
        method=getattr(root._OwnedCallRuntime,name,None)
        incomplete(method is not None,'call_runtime_registration_pending')
    except (ImportError,AttributeError) as error:
        raise ProbeError('INCOMPLETE','call_runtime_registration_pending') from error
    return method(registration._owner,wire,*args,**kwargs)


def _native(kind,**fields):
    value=object.__new__(kind)
    deny(set(fields)==set(kind.__dataclass_fields__),'call_native_fields')
    for name,item in fields.items():object.__setattr__(value,name,item)
    return value


@dataclass(frozen=True,slots=True)
class WirePosition:
    stream:str
    offset:int
    length:int

@dataclass(frozen=True,slots=True)
class Operation:
    seq:int
    charged_epoch:str
    protocol:str
    operation:str
    started_ns:int
    finished_ns:int|None=None
    request:WirePosition|None=None
    response:WirePosition|None=None
    result:str='pending'

@dataclass(frozen=True,slots=True)
class Event:
    seq:int
    protocol:str
    name:str
    wire:WirePosition
    received_ns:int
    receive_ordinal:int
    state:str
    confirmed_epoch:str|None
    target_epoch:str|None
    cause_epoch:str|None
    flight_id:str|None

@dataclass(frozen=True,slots=True)
class EndOfStream:
    stream:str
    observed_ns:int

@dataclass(frozen=True,slots=True)
class StreamError:
    stream:str
    operation:str
    errno:int|None
    observed_ns:int

@dataclass(frozen=True,slots=True)
class Failure:
    status:str
    reason:str

@dataclass(frozen=True,slots=True)
class Prelaunch:
    commands:tuple
    observed_ns:int

class _Private:
    def __init__(self,*args,**kwargs):
        raise TypeError('only the exact held parent wire issues this receipt')

@dataclass(frozen=True,slots=True,init=False)
class EpochStopReceipt(_Private):
    _registration:object
    _wire:object
    epoch:str
    stop_nonce:object
    flight:object
    target:object
    stop_event_seq:int
    stop_ack_operation_seq:int
    debug_operation_seq:int
    received_ns:int
    confirmed_ns:int
    stop_deadline_ns:int

@dataclass(frozen=True,slots=True,init=False)
class SelectedEpochRegisters(_Private):
    _registration:object
    _wire:object
    stop:EpochStopReceipt
    phase:str
    values:tuple

@dataclass(frozen=True,slots=True,init=False)
class CurrentEpochMode(_Private):
    _registration:object
    _wire:object
    stop:EpochStopReceipt
    operation_seq:int
    value:int

@dataclass(frozen=True,slots=True,init=False)
class ParentHostLease(_Private):
    _registration:object
    _wire:object
    stop:EpochStopReceipt
    before_registers:SelectedEpochRegisters
    started_ns:int
    deadline_ns:int

@dataclass(frozen=True,slots=True,init=False)
class ParentPeerReceipt(_Private):
    _registration:object
    _wire:object
    lease:ParentHostLease
    raw_bytes:bytes
    observed_ns:int

@dataclass(frozen=True,slots=True,init=False)
class ParentHostBracket(_Private):
    _registration:object
    _wire:object
    lease:ParentHostLease
    phase:str
    operations:tuple
    cpu_identity:tuple
    hmp_bytes:bytes
    parsed_state:tuple

@dataclass(frozen=True,slots=True,init=False)
class EpochRegisterView(_Private):
    _registration:object
    _wire:object
    stop:EpochStopReceipt
    registers:SelectedEpochRegisters
    operation_seq:int
    wire:WirePosition
    raw_bytes:bytes
    parsed_state:tuple

@dataclass(frozen=True,slots=True,init=False)
class EpochLayoutReceipt(_Private):
    _registration:object
    _wire:object
    stop:EpochStopReceipt
    phase:str
    operation_seq:int
    wire:WirePosition
    raw_bytes:bytes
    ranges:tuple

@dataclass(frozen=True,slots=True,init=False)
class EpochAfterReceipt(_Private):
    _registration:object
    _wire:object
    stop:EpochStopReceipt
    reads_complete:object
    registers:SelectedEpochRegisters
    hmp:EpochRegisterView
    layout:EpochLayoutReceipt

@dataclass(frozen=True,slots=True)
class FlightRecord:
    target_epoch:str
    source_epoch:str|None
    source_closure_ref:object
    clear_operation_seq:int|None
    set_operation_seq:int
    admission_ref:object
    resume_operation_seq:int|None=None
    c_sent_slice:WirePosition|None=None
    c_complete_ns:int|None=None
    request_ack_slice:WirePosition|None=None
    request_ack_received_ns:int|None=None
    qmp_resume_event_seq:int|None=None
    qmp_stop_event_seq:int|None=None
    rsp_stop_event_seq:int|None=None
    stop_ack_operation_seq:int|None=None
    debug_operation_seq:int|None=None
    response_deadline_ns:int|None=None
    stop_deadline_ns:int|None=None
    result:str='pending'

@dataclass(frozen=True,slots=True,init=False)
class ParentDrainReceipt(_Private):
    _registration:object
    _wire:object
    closed:object
    quit_operation:Operation|None
    eofs:tuple
    io_errors:tuple
    observed_ns:int
    failure:Failure|None


class _ParentAckDecoder:
    """Same strict AckCodec grammar with charging before each bounded growth.

    A fixed exact wire receives frames. No decoder callback is configurable.
    The seven-per-input-byte copy envelope is inventoried separately from the
    retainer's independent verification decoder.
    """
    def __init__(self,wire):
        deny(type(wire) is CallWire,'call_decoder_owner')
        self.wire=wire;self._buffer=bytearray();self._state='idle';self._end=None
        self._failed=False;self._frames=0
    @property
    def pending(self):return bool(self._buffer)
    def feed(self,data,observed):
        deny(not self._failed and type(data) is bytes,'call_rsp_decoder_state')
        try:
            for value in data:
                if self._state=='idle':
                    if value in (43,45):
                        self._reserve_frame()
                        self._emit(rsp.Frame('ACK' if value==43 else 'NACK',raw=bytes([value])),observed)
                        continue
                    deny(value==36,'rsp_frame_start');self._buffer.append(value);self._state='payload';continue
                incomplete(len(self._buffer)<rsp.MAX_PACKET,'rsp_packet_limit')
                self._buffer.append(value)
                if self._state=='payload':
                    deny(value!=36,'rsp_nested_packet')
                    if value==35:self._end=len(self._buffer)-1;self._state='checksum1'
                elif self._state=='checksum1':
                    deny(value in b'0123456789abcdefABCDEF','rsp_checksum_digits');self._state='checksum2'
                else:
                    deny(value in b'0123456789abcdefABCDEF','rsp_checksum_digits')
                    # Bytes already charged5x across every input chunk before feed:
                    # buffer,raw,encoded,decoded-array,payload. Charge row before
                    # its native publication; no row is an admitted read.
                    self._reserve_frame()
                    raw=bytes(self._buffer);encoded=raw[1:self._end]
                    deny(sum(encoded)&255==int(raw[-2:],16),'rsp_checksum')
                    decoded=bytearray();escape=False
                    for byte in encoded:
                        if escape:
                            incomplete(len(decoded)<rsp.MAX_PAYLOAD,'rsp_payload_limit');decoded.append(byte^32);escape=False
                        elif byte==125:escape=True
                        else:
                            incomplete(byte!=42,'rsp_rle_unsupported')
                            incomplete(len(decoded)<rsp.MAX_PAYLOAD,'rsp_payload_limit');decoded.append(byte)
                    deny(not escape,'rsp_escape_truncated')
                    self._emit(rsp.Frame('PACKET',bytes(decoded),raw),observed)
                    self._buffer.clear();self._state='idle';self._end=None
        except BaseException:
            self._failed=True;raise
    def _reserve_frame(self):
        incomplete(self._frames<MAX_RSP_FRAMES,'rsp_frame_inventory')
        if self.wire._active_pending is not None and not self.wire._failed_draining:
            incomplete(self.wire._physical_frames<3,'call_physical_frame_limit')
            self.wire._physical_frames+=1
        self.wire._charge(FRAME_CREDIT)
    def _emit(self,frame,observed):
        self._frames+=1;self.wire._receive_rsp(frame,observed)


class CallWire:
    def __init__(self,*args,**kwargs):
        raise TypeError('only the owned parent graph initializes CallWire')

    def _init_inert(self,registration,qmp,streams):
        # No fileno/fstat/getsockopt/selector/read/write/host observation here.
        try:
            root=importlib.import_module('run0_call_capture')
            deny(type(registration) is root.ClosedOwnedCallRegistration,'call_registration_type')
        except ImportError as e:raise ProbeError('INCOMPLETE','call_runtime_registration_pending') from e
        deny(type(streams) is dict and tuple(streams)==STREAMS,'call_stream_inventory')
        deny(type(registration.deadlines) is ParentDeadlines and type(registration.accounting) is ParentAccounting
             and registration.deadlines.started_ns==registration.accounting.started_ns,'call_ledger_origin')
        self._registration=registration;self._qmp=qmp;self._streams=dict(streams);self._rsp_socket=streams['rsp']
        self._policy=registration.deadlines;self._accounting=registration.accounting
        self._read_attempts=registration.read_attempts;self._read_operations=registration.read_operations
        self._selector=None;self._read_buffer=None;self._closed=False;self._used=False;self._failure=None
        self._raw={n:bytearray() for n in ('qmp-in',*STREAMS,'qmp-out','rsp-out')}
        self._operations=[];self._events=[];self._eofs=[];self._io_errors=[];self._frames=deque();self._rsp_frames=deque()
        self._frame_start=self._scan_at=self._frame_count=self._receive_ordinal=self._qmp_identifier=0
        self._qmp_eof=self._rsp_eof=False;self._rsp_offset=self._rsp_acks=self._rsp_segments=0
        self._state='RESET';self._epoch='C0';self._confirmed_epoch=None;self._flight_index=None;self._flights=[]
        self._ever_resumed=False;self._greeted=self._prelaunch_complete=self._rsp_ready=False
        self._rsp_active=False;self._rsp_decoder=None;self._reset=None;self._breakpoint=None
        self._stop=self._current_mode=self._before_registers=self._after_registers=None
        self._host_lease=self._host_peer=self._host_before=self._host_after=self._host_receipt=None
        self._layout_before=self._layout_after=self._final_register_view=self._after_receipt=None
        self._registered_binding=self._session=self._reads_complete=None
        self._active_pending=self._active_attempt=None;self._physical_start=None
        self._transition_closed=self._transition_target=self._transition_clear=self._transition_set=None
        self._transition_quiet_ns=None;self._ticket=None;self._terminal_closed=None
        self._quit=None;self._quit_reply=self._quit_shutdown=None;self._quit_deadline=None;self._drain=None
        self._qmp_damaged=False;self._rsp_damaged=False
        self._recognized_ordinals={};self._qmp_frame_rows=[];self._rsp_frame_rows=[];self._rsp_segment_rows=[]
        self._flight_rsp=None;self._flight_target=None;self._transition_started_ns=None;self._failed_draining=False;self._physical_frames=0

    def close(self):
        if not self._closed:
            if self._used and self._drain is None:self._latch_failure(Failure('INCOMPLETE','call_wire_closed'))
            self._closed=True
            if self._selector is not None:self._selector.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    @property
    def operations(self):return self._snapshot(self._operations)
    @property
    def events(self):return self._snapshot(self._events)
    @property
    def eofs(self):return self._snapshot(self._eofs)
    @property
    def io_errors(self):return self._snapshot(self._io_errors)
    @property
    def failure(self):return self._failure
    @property
    def flights(self):return self._snapshot(self._flights)
    def _snapshot(self,rows):
        self._accounting.reserve_output(8*len(rows));return tuple(rows)
    def raw(self,stream):
        deny(type(stream) is str and stream in self._raw,'call_raw_stream')
        self._accounting.reserve_output(len(self._raw[stream]));return bytes(self._raw[stream])
    def reserve_output(self,count):self._accounting.reserve_output(count)
    def _charge(self,count):
        if self._active_pending is None or self._failed_draining:self._accounting.reserve_output(count)
        else:
            # Runtime-only prepaid credit is deliberately a separately reviewed
            # receiving dependency. Legacy read8L+2048 is not presumed sufficient.
            fn=getattr(type(self._accounting),'debit_wire_read',None)
            incomplete(fn is not None,'call_wire_credit_pending')
            fn(self._accounting,self._active_pending.reservation,self._active_pending.key,count)
    @staticmethod
    def _time_left(deadline,reason):
        remaining=deadline-time.monotonic_ns();incomplete(remaining>0,reason);return remaining/SECOND
    def _limit(self):
        stop=self._stop.stop_deadline_ns if self._stop is not None else self._policy.effective_work_ns
        return min(stop,self._policy.effective_work_ns)
    def _latch_failure(self,failure):
        if self._failure is None:self._failure=failure
        self._state='FAILED'
        try:_root_guard(self,'_abort_wire_epoch',self._failure)
        except BaseException:pass  # preserve the first cause; failed abort cannot repair authority
    @contextmanager
    def _attempt(self):
        try:yield
        except BaseException as e:
            if isinstance(e,ProbeError):failure=Failure(e.status,e.reason)
            elif isinstance(e,rsp.RSPError):failure=Failure(e.status,e.reason)
            elif isinstance(e,KeyboardInterrupt):failure=Failure('INCOMPLETE','call_cancelled')
            elif isinstance(e,OSError):failure=Failure('INCOMPLETE','call_io_error')
            else:failure=Failure('INCOMPLETE','call_internal_failure')
            self._latch_failure(failure)
            if isinstance(e,(OSError,rsp.RSPError)):raise ProbeError(failure.status,failure.reason) from e
            raise
    @contextmanager
    def _epoch_attempt(self,stop):
        with self._attempt():
            self._current_stop(stop)
            yield
    def _activate_io(self):
        if self._selector is not None:return
        # Root validates actual descriptor inventory and ownership before guard.
        self._accounting.reserve_output(READ_CHUNK)
        buffer=bytearray(READ_CHUNK);selector=selectors.DefaultSelector()
        try:
            for name,source in {'qmp-in':self._qmp,**self._streams}.items():
                selector.register(source,selectors.EVENT_READ,name)
        except BaseException:selector.close();raise
        self._read_buffer=buffer;self._selector=selector
    def _account_operation(self,name,*,physical=False):
        incomplete(len(self._operations)<MAX_OPERATIONS,'call_operation_limit')
        if not physical:
            kind='bootstrap:'+name if not self._rsp_ready else name
            self._accounting.reserve_operation(self._epoch,kind)
        self._charge(ROW_CREDIT)
    def _new_operation(self,protocol,name,*,physical=False):
        self._account_operation(name,physical=physical)
        row=Operation(len(self._operations)+1,self._epoch,protocol,name,time.monotonic_ns())
        self._operations.append(row);return len(self._operations)-1,row
    def _finish_operation(self,index,row,offset,request_limit,response,result,finished=None):
        stream='qmp-out' if row.protocol=='qmp' else 'rsp-out';length=min(len(self._raw[stream])-offset,request_limit)
        self._operations[index]=replace(row,finished_ns=time.monotonic_ns() if finished is None else finished,
            request=WirePosition(stream,offset,length) if length else None,response=response,result=result)
    def _poll(self,deadline,reason,*,wait=True,writing=None,drain=False):
        if not drain:incomplete(not self._qmp_eof,'qmp_eof')
        source=self._rsp_socket if writing=='rsp' else self._qmp
        if writing:self._selector.modify(source,selectors.EVENT_READ|selectors.EVENT_WRITE,'rsp' if writing=='rsp' else 'qmp-in')
        try:
            while True:
                try:ready=self._selector.select(self._time_left(deadline,reason) if wait else 0);break
                except InterruptedError:
                    self._time_left(deadline,reason)
                    continue
            for key,mask in ready:
                if mask&selectors.EVENT_READ:self._read(key,deadline,reason,drain=drain)
        finally:
            if writing and source.fileno() in self._selector.get_map():
                self._selector.modify(source,selectors.EVENT_READ,'rsp' if writing=='rsp' else 'qmp-in')
    def _read(self,key,deadline,reason,*,drain=False):
        self._time_left(deadline,reason)
        count=READ_CHUNK
        if key.data=='qmp-in':
            count=min(count,MAX_QMP_BYTES-len(self._raw['qmp-in']));incomplete(count>0,'qmp_wire_limit')
        if key.data=='rsp' and self._physical_start is not None and not drain:
            count=min(count,2*self._active_pending.target.length+6-(len(self._raw['rsp'])-self._physical_start))
            incomplete(count>0,'call_physical_tail')
        try:n=os.readv(key.fd,[memoryview(self._read_buffer)[:count]])
        except (BlockingIOError,InterruptedError):return
        except OSError as e:
            self._accounting.reserve_output(FRAME_CREDIT)
            self._io_errors.append(StreamError(key.data,'read',e.errno,time.monotonic_ns()));raise
        observed=time.monotonic_ns()
        if n==0:
            self._accounting.reserve_output(FRAME_CREDIT)
            self._selector.unregister(key.fileobj);self._eofs.append(EndOfStream(key.data,observed))
            if key.data=='qmp-in':self._qmp_eof=True
            if key.data=='rsp':self._rsp_eof=True
            return
        # Prepaid fixed readv buffer already owns incoming bytes. Charge before
        # every copied chunk/raw extension/decoder growth; no post-copy debit.
        if key.data=='rsp' and self._rsp_active and not self._rsp_damaged:
            self._charge(7*n)
        else:self._accounting.reserve_output(2*n)
        data=bytes(memoryview(self._read_buffer)[:n]);self._raw[key.data].extend(data)
        try:
            if key.data=='qmp-in' and not self._qmp_damaged:self._qmp_frames(observed)
            elif key.data=='rsp' and self._rsp_active and not self._rsp_damaged:self._rsp_decoder.feed(data,observed)
        except BaseException:
            if key.data=='qmp-in':self._qmp_damaged=True
            elif key.data=='rsp':self._rsp_damaged=True
            if not drain:raise
            self._latch_failure(Failure('INCOMPLETE','call_failed_tail'))
    def _decode(self,position):
        self._accounting.reserve_output(8*position.length+FRAME_CREDIT)
        return decode_frame(bytes(memoryview(self._raw[position.stream])[position.offset:position.offset+position.length]))
    def _qmp_frames(self,observed):
        raw=self._raw['qmp-in']
        while (end:=raw.find(b'\n',self._scan_at))>=0:
            length=end-self._frame_start-1
            deny(length>0 and raw[end-1]==13 and raw.find(b'\r',self._frame_start,end-1)<0,'qmp_wire_framing')
            incomplete(length<=MAX_FRAME and self._frame_count<MAX_QMP_FRAMES,'qmp_frame_limit')
            pos=WirePosition('qmp-in',self._frame_start,length);value=self._decode(pos)
            self._receive_ordinal+=1;self._frame_count+=1
            self._recognized_ordinals[('qmp-in',pos.offset,pos.length)]=self._receive_ordinal
            self._qmp_frame_rows.append((WirePosition('qmp-in',pos.offset,pos.length+2),observed,self._receive_ordinal))
            self._frame_start=self._scan_at=end+1
            if 'event' in value:self._event(value,pos,observed)
            else:
                self._accounting.reserve_output(FRAME_CREDIT);self._frames.append((value,pos,observed))
        self._scan_at=len(raw)
        incomplete(len(raw)-self._frame_start<=MAX_FRAME+int(raw.endswith(b'\r')),'qmp_frame_limit')
    def _receive_rsp(self,frame,observed):
        pos=WirePosition('rsp',self._rsp_offset,len(frame.raw));self._rsp_offset+=len(frame.raw)
        self._receive_ordinal+=1
        self._recognized_ordinals[('rsp',pos.offset,pos.length)]=self._receive_ordinal
        self._rsp_frame_rows.append((frame.kind,pos,observed,self._receive_ordinal))
        if frame.kind in ('ACK','NACK'):
            incomplete(self._rsp_acks<MAX_RSP_ACKS,'rsp_ack_limit');self._rsp_acks+=1
        if self._state=='FLIGHT':
            if self._flight_rsp=='ack':
                rsp.require(frame.kind=='ACK','rsp_request_ack',status='INCOMPLETE' if frame.kind=='NACK' else 'DENY')
                self._flight_rsp='stop'
            elif self._flight_rsp=='stop':
                deny(frame.kind=='PACKET' and frame.payload==b'T05thread:01;','rsp_stop_identity')
                seq=self._record_event('rsp','T05thread:01;',pos,observed,self._flights[self._flight_index].target_epoch)
                self._flights[self._flight_index]=replace(self._flights[self._flight_index],rsp_stop_event_seq=seq)
                self._flight_rsp='done'
            else:raise ProbeError('DENY','rsp_flight_extra')
        self._rsp_frames.append((frame,pos,observed))
    def _record_event(self,protocol,name,pos,observed,flight):
        incomplete(len(self._events)<MAX_EVENTS,'call_event_limit');self._accounting.reserve_output(FRAME_CREDIT)
        target=self._flights[self._flight_index].target_epoch if self._flight_index is not None and self._state in ('C_DISPATCH','FLIGHT','STOP_ACK','DEBUG_FENCE') else None
        self._events.append(Event(len(self._events)+1,protocol,name,pos,observed,self._receive_ordinal,
            self._state,self._confirmed_epoch,target,flight,flight))
        return len(self._events)
    def _event(self,value,pos,observed):
        name=value.get('event')
        # Reception context is evidence even when the event is refused. Causal
        # flight attribution is added only after the active-flight checks below.
        seq=self._record_event('qmp',name,pos,observed,None)
        stamp=value.get('timestamp');deny(type(stamp) is dict and set(stamp)=={'seconds','microseconds'}
            and type(stamp['seconds']) is int and 0<=stamp['seconds']<(1<<63)
            and type(stamp['microseconds']) is int and 0<=stamp['microseconds']<1_000_000,'qmp_event_timestamp')
        if name=='RTC_CHANGE':
            data=value.get('data');deny(set(value)=={'event','timestamp','data'} and type(data) is dict
                and set(data)=={'offset','qom-path'} and type(data['offset']) is int and -(1<<63)<=data['offset']<(1<<63)
                and data['qom-path']=='/machine/unattached/device[1]/rtc' and self._ever_resumed,'call_rtc_event')
            return
        if name=='SHUTDOWN':
            deny(set(value)=={'event','timestamp','data'} and value['data']=={'guest':False,'reason':'host-qmp-quit'}
                and type(value['data']['guest']) is bool and self._state in ('QUIT_WAIT','DRAIN')
                and self._quit_shutdown is None,'call_shutdown_event')
            self._quit_shutdown=seq;return
        deny(name in ('RESUME','STOP') and set(value)=={'event','timestamp'}
            and self._state in ('FLIGHT','STOP_ACK','DEBUG_FENCE') and self._flight_index is not None,'call_flight_event')
        f=self._flights[self._flight_index]
        if name=='RESUME':
            deny(f.c_complete_ns is not None and f.qmp_resume_event_seq is None and f.qmp_stop_event_seq is None,'call_resume_order')
            self._ever_resumed=True;f=replace(f,qmp_resume_event_seq=seq)
        else:
            deny(f.qmp_resume_event_seq is not None and f.qmp_stop_event_seq is None,'call_stop_order');f=replace(f,qmp_stop_event_seq=seq)
        self._events[seq-1]=replace(self._events[seq-1],cause_epoch=f.target_epoch,flight_id=f.target_epoch)
        self._flights[self._flight_index]=f
    def _quiet(self,deadline):
        self._poll(deadline,'call_quiet_timeout',wait=False)
        deny(not self._frames and self._frame_start==len(self._raw['qmp-in']),'qmp_unsolicited')
        incomplete(not self._qmp_eof,'qmp_eof')
        if self._rsp_active:
            deny(not self._rsp_frames and not self._rsp_decoder.pending,'rsp_unsolicited')
            incomplete(not self._rsp_eof,'rsp_eof')
    def _next_qmp(self,deadline):
        while not self._frames:
            self._poll(deadline,'qmp_response_timeout')
        self._time_left(deadline,'qmp_response_timeout');return self._frames.popleft()
    def _next_rsp(self,deadline,reason='rsp_response_timeout'):
        while not self._rsp_frames:
            incomplete(not self._rsp_eof,'rsp_eof');self._poll(deadline,reason)
            deny(not self._frames and self._frame_start==len(self._raw['qmp-in']),'qmp_unsolicited')
        self._time_left(deadline,reason);return self._rsp_frames.popleft()
    def _send(self,data,deadline,*,protocol,attempt=None,ticket=None):
        endpoint=self._qmp if protocol=='qmp' else self._rsp_socket;stream='qmp-out' if protocol=='qmp' else 'rsp-out'
        view=memoryview(data)
        while view:
            self._dispatch_guard()
            self._time_left(deadline,'call_request_timeout')
            if attempt is not None:_root_guard(self,'_recheck_wire_read',attempt)
            if ticket is not None:_root_guard(self,'_require_wire_resume',ticket)
            if protocol=='rsp':incomplete(self._rsp_segments<MAX_RSP_SEGMENTS,'rsp_segment_limit')
            # Segment metadata is charged before each possible effect. EAGAIN
            # can consume credit but never refund, repeat admission or renew time.
            if attempt is None:self._charge(FRAME_CREDIT)
            try:n=endpoint.send(view)
            except (BlockingIOError,InterruptedError):
                self._poll(deadline,'call_request_timeout',writing=protocol)
                self._quiet(deadline);continue
            except OSError as e:
                self._accounting.reserve_output(FRAME_CREDIT)
                self._io_errors.append(StreamError(stream,'write',e.errno,time.monotonic_ns()));raise
            incomplete(n>0,'call_send_eof');self._raw[stream].extend(view[:n]);view=view[n:]
            if protocol=='rsp':
                self._rsp_segments+=1;self._rsp_segment_rows.append((WirePosition(stream,len(self._raw[stream])-n,n),time.monotonic_ns()))
            if view:self._quiet(deadline)
    @staticmethod
    def _value(command,value,*,debug=False):
        if command=='qmp_capabilities':deny(type(value) is dict and value=={},'qmp_capabilities_reply')
        elif command=='query-commands':
            deny(type(value) is list and all(type(r) is dict and set(r)=={'name'} and type(r['name']) is str for r in value),'qmp_command_inventory')
            names=tuple(r['name'] for r in value);deny(len(set(names))==len(names) and set(_REQUIRED_COMMANDS)<=set(names),'qmp_command_inventory');return names
        elif command=='query-status':
            incomplete(type(value) is dict and set(value)=={'running','singlestep','status'} and value['running'] is False
                and value['singlestep'] is False and value['status']==('debug' if debug else 'prelaunch'),'qmp_not_debug' if debug else 'qmp_not_prelaunch')
        else:return value
    def _qmp_exchange(self,command,name,arguments,limit,*,debug=False):
        deny(not self._closed and self._failure is None,'call_wire_failed');self._quiet(limit)
        identifier=self._qmp_identifier+1
        value={'execute':command,'id':identifier}
        if arguments is not None:value['arguments']=arguments
        # Closed tiny request objects only; fixed bound precedes JSON growth.
        self._charge(8192);request=json.dumps(value,separators=(',',':')).encode()+b'\r\n'
        incomplete(len(request)<=2048 and len(self._raw['qmp-out'])+len(request)<=MAX_QMP_BYTES,'qmp_request_bound')
        index,row=self._new_operation('qmp',name);self._qmp_identifier=identifier;offset=len(self._raw['qmp-out'])
        deadline=min(row.started_ns+RESPONSE_NS,self._policy.effective_work_ns,limit);response=None;result='error';finished=None
        try:
            self._send(request,deadline,protocol='qmp');reply,pos,observed=self._next_qmp(deadline)
            deny(set(reply) in ({'return','id'},{'error','id'}) and type(reply['id']) is int and reply['id']==identifier,'qmp_response_identity')
            incomplete('error' not in reply,'qmp_command_error');answer=self._value(command,reply['return'],debug=debug)
            if self._state=='DEBUG_FENCE':
                f=self._flights[self._flight_index];incomplete(f.qmp_resume_event_seq is not None and f.qmp_stop_event_seq is not None,'call_pair_missing')
                ordinal=self._recognized_ordinals[('qmp-in',pos.offset,pos.length)]
                deny(all(self._events[seq-1].receive_ordinal<ordinal for seq in (f.qmp_resume_event_seq,f.qmp_stop_event_seq)),'call_debug_fence_order')
            response=pos;finished=observed;result='ok';return answer,observed
        except ProbeError as e:
            if 'timeout' in e.reason:result='timeout'
            raise
        finally:self._finish_operation(index,row,offset,len(request),response,result,finished)
    def prelaunch(self):
        _root_guard(self,'_require_wire_bootstrap');deny(not self._used and not self._closed,'call_prelaunch_once');self._used=True
        with self._attempt():
            self._activate_io();deadline=min(time.monotonic_ns()+RESPONSE_NS,self._limit())
            greeting,_,_=self._next_qmp(deadline);deny(set(greeting)=={'QMP'} and type(greeting['QMP']) is dict,'qmp_greeting');self._greeted=True
            commands=None;observed=None
            for command in _COMMANDS:
                value,observed=self._qmp_exchange(command,command.replace('-','_'),None,deadline)
                if command=='query-commands':commands=value
            self._quiet(deadline);self._prelaunch_complete=True;return Prelaunch(commands,observed)

    def _dispatch_guard(self):
        deny(not self._closed and self._failure is None,'call_wire_failed')
        if self._active_attempt is not None:
            return _root_guard(self,'_recheck_wire_read',self._active_attempt)
        if self._state=='STOPPED':return _root_guard(self,'_require_wire_stop',self._stop)
        if self._state=='TRANSITION_PREP':
            return _root_guard(self,'_require_wire_transition',self._transition_closed,self._transition_target)
        if self._state in ('TERMINAL_CLEAR','QUIT_DISPATCH','QUIT_WAIT','DRAIN'):
            return _root_guard(self,'_require_wire_termination',self._terminal_closed)
        if self._ticket is not None and self._state in ('C_DISPATCH','FLIGHT','STOP_ACK','DEBUG_FENCE'):
            return _root_guard(self,'_require_wire_resume',self._ticket)
        return _root_guard(self,'_require_wire_bootstrap')

    def _rsp_semantic(self,reason,status):
        if self._operations:self._operations[-1]=replace(self._operations[-1],result='error')
        raise ProbeError(status,reason)

    def _rsp_exchange(self,name,payload,*,limit=None):
        self._dispatch_guard()
        deny(self._rsp_active and type(payload) is bytes,'call_rsp_state')
        limit=self._limit() if limit is None else min(limit,self._limit())
        self._quiet(limit)
        incomplete(self._rsp_acks<=MAX_RSP_ACKS-2,'rsp_ack_limit')
        # Includes closed request payload/framing temporaries and held raw copy.
        self._charge(8*(len(payload)+4)+FRAME_CREDIT)
        request=rsp.encode_packet(payload);index,row=self._new_operation('rsp',name)
        deadline=min(row.started_ns+RESPONSE_NS,limit);offset=len(self._raw['rsp-out'])
        response=None;result='error'
        try:
            self._send(request,deadline,protocol='rsp')
            ack,_,_=self._next_rsp(deadline)
            rsp.require(ack.kind=='ACK','rsp_request_ack',status='INCOMPLETE' if ack.kind=='NACK' else 'DENY')
            packet,pos,_=self._next_rsp(deadline);deny(packet.kind=='PACKET','rsp_response_packet');response=pos
            self._quiet(deadline);incomplete(self._rsp_acks<MAX_RSP_ACKS,'rsp_ack_limit')
            self._charge(1);self._send(b'+',deadline,protocol='rsp');self._rsp_acks+=1
            self._time_left(deadline,'rsp_response_timeout')
            incomplete(bool(packet.payload),'rsp_unsupported')
            incomplete(not(len(packet.payload)==3 and packet.payload[:1]==b'E' and rsp.HEX.fullmatch(packet.payload[1:])),'rsp_remote_error')
            result='ok';return packet.payload
        except ProbeError as e:
            if 'timeout' in e.reason:result='timeout'
            raise
        finally:self._finish_operation(index,row,offset,len(request),response,result)

    def prepare_reset(self):
        _root_guard(self,'_require_wire_bootstrap')
        deny(self._prelaunch_complete and not self._rsp_active and not self._closed,'call_reset_once')
        with self._attempt():
            deny(not self._raw['rsp'],'rsp_unsolicited');incomplete(not self._rsp_eof,'rsp_eof')
            self._charge(262144) # bounded shared reset semantic/XML/native-row envelope
            self._rsp_decoder=_ParentAckDecoder(self);self._rsp_active=True;self._quiet(self._limit())
            sequence=_ParentReset(self);result=sequence.prepare()
            self._reset=result;self._rsp_ready=True;return result

    def stop_at_entry(self,prior_entry):
        _root_guard(self,'_require_wire_bootstrap')
        deny(self._rsp_ready and self._state=='RESET' and self._breakpoint is None,'call_initial_entry_once')
        from run0_c0_entry import export_validated_prior_entry
        from run0_c0_paging import C0DecodeError
        from boot_profile_capture import VAPIC_OFF_INVOCATION_PROFILE
        try:entry=export_validated_prior_entry(prior_entry)
        except C0DecodeError as e:raise ProbeError(e.status,e.reason) from e
        deny(entry['invocation_profile']==VAPIC_OFF_INVOCATION_PROFILE,'call_exact_profile')
        with self._attempt():
            self._charge(512);payload=f"Z1,{entry['entry_address']:x},1".encode()
            reply=self._rsp_exchange('hardware_breakpoint_set',payload)
            if reply!=b'OK':self._rsp_semantic('rsp_breakpoint_reply','DENY')
            self._breakpoint=(entry['entry_address'],self._operations[-1].seq,prior_entry)
            return self._start_flight('C0',prior_entry,None,None)

    def _start_flight(self,target_epoch,target,closed,ticket):
        deny(self._breakpoint is not None and self._failure is None,'call_flight_state')
        self._state='C_DISPATCH';self._flight_target=target;self._ticket=ticket
        source=None if target_epoch=='C0' else self._epoch
        closure=None if target_epoch=='C0' else target.source_closure_ref
        clear=None if target_epoch=='C0' else self._transition_clear.seq
        admission=None if ticket is None else ticket.journal_ref
        self._charge(ROW_CREDIT)
        self._flights.append(FlightRecord(target_epoch,source,closure,clear,self._breakpoint[1],admission))
        self._flight_index=len(self._flights)-1
        try:
            self._continue_ack(ticket)
            packet,pos,observed=self._next_rsp(self._flights[self._flight_index].stop_deadline_ns,'rsp_stop_timeout')
            deny(packet.kind=='PACKET' and packet.payload==b'T05thread:01;','rsp_stop_identity')
            f=self._flights[self._flight_index]
            deny(f.rsp_stop_event_seq is not None and f.request_ack_received_ns<=observed,'rsp_stop_clock')
            self._state='STOP_ACK';self._ack_stop(observed)
            self._state='DEBUG_FENCE'
            _,confirmed=self._qmp_exchange('query-status','query_status',None,self._flights[self._flight_index].stop_deadline_ns,debug=True)
            debug=self._operations[-1].seq;self._quiet(self._flights[self._flight_index].stop_deadline_ns)
            f=replace(self._flights[self._flight_index],debug_operation_seq=debug,result='ok')
            self._flights[self._flight_index]=f
            self._stop=_native(EpochStopReceipt,_registration=self._registration,_wire=self,epoch=target_epoch,
                stop_nonce=object(),flight=f,target=target,stop_event_seq=f.rsp_stop_event_seq,
                stop_ack_operation_seq=f.stop_ack_operation_seq,debug_operation_seq=debug,
                received_ns=observed,confirmed_ns=confirmed,
                stop_deadline_ns=min(observed+60*SECOND,self._policy.effective_work_ns))
            self._confirmed_epoch=target_epoch;self._state='STOPPED';return self._stop
        except BaseException:
            self._flights[self._flight_index]=replace(self._flights[self._flight_index],result='error');raise

    def _continue_ack(self,ticket):
        self._quiet(self._policy.effective_work_ns)
        incomplete(self._rsp_acks<MAX_RSP_ACKS,'rsp_ack_limit')
        started=time.monotonic_ns()
        deadline=min(started+RESPONSE_NS,self._policy.effective_work_ns) if ticket is None else ticket.response_deadline_ns
        stop_deadline=min(started+60*SECOND,self._policy.effective_work_ns) if ticket is None else ticket.next_stop_deadline_ns
        f=self._flights[self._flight_index]
        self._flights[self._flight_index]=replace(f,response_deadline_ns=deadline,stop_deadline_ns=stop_deadline)
        self._charge(64);request=rsp.encode_packet(b'c');index,row=self._new_operation('rsp','continue')
        offset=len(self._raw['rsp-out']);response=None;result='error';finished=None
        try:
            if ticket is not None:
                self._registration.transition_owner.consume_for_send(ticket,now_ns=time.monotonic_ns())
            self._send(request,deadline,protocol='rsp',ticket=ticket)
            complete=time.monotonic_ns();self._time_left(deadline,'rsp_request_timeout')
            self._flights[self._flight_index]=replace(self._flights[self._flight_index],resume_operation_seq=row.seq,
                c_sent_slice=WirePosition('rsp-out',offset,len(request)),c_complete_ns=complete)
            self._state='FLIGHT';self._flight_rsp='ack';self._epoch=f.target_epoch
            if ticket is not None:self._retire_stop_slots()
            ack,pos,observed=self._next_rsp(deadline)
            rsp.require(ack.kind=='ACK','rsp_request_ack',status='INCOMPLETE' if ack.kind=='NACK' else 'DENY')
            response=pos;finished=observed;result='ok'
            self._flights[self._flight_index]=replace(self._flights[self._flight_index],request_ack_slice=pos,request_ack_received_ns=observed)
        finally:
            self._finish_operation(index,row,offset,len(request),response,result,finished)
            # Actual allocated/partial c is retained even when no complete send.
            if self._flights[self._flight_index].resume_operation_seq is None:
                self._flights[self._flight_index]=replace(self._flights[self._flight_index],resume_operation_seq=row.seq,
                    c_sent_slice=self._operations[index].request)

    def _ack_stop(self,observed):
        limit=self._flights[self._flight_index].stop_deadline_ns;self._quiet(limit)
        incomplete(self._rsp_acks<MAX_RSP_ACKS,'rsp_ack_limit')
        self._charge(1);index,row=self._new_operation('rsp','stop_ack')
        deny(row.started_ns>=observed,'rsp_stop_ack_clock')
        deadline=min(row.started_ns+RESPONSE_NS,limit);offset=len(self._raw['rsp-out']);result='error'
        try:
            incomplete(self._rsp_acks<MAX_RSP_ACKS,'rsp_ack_limit');self._send(b'+',deadline,protocol='rsp')
            self._rsp_acks+=1;self._time_left(deadline,'rsp_response_timeout');result='ok'
            self._flights[self._flight_index]=replace(self._flights[self._flight_index],stop_ack_operation_seq=row.seq)
        finally:self._finish_operation(index,row,offset,1,None,result)

    def _current_stop(self,stop):
        _root_guard(self,'_require_wire_stop',stop)
        deny(type(stop) is EpochStopReceipt and stop is self._stop
            and stop._registration is self._registration and stop._wire is self
            and stop.epoch==self._epoch and self._state=='STOPPED'
            and self._failure is None and not self._closed,'call_current_stop')
        self._time_left(self._limit(),'call_stop_deadline')

    def confirm_stopped_physical_mode(self,stop):
        with self._epoch_attempt(stop):
            deny(self._current_mode is None and self._before_registers is None,'call_mode_state')
            if self._rsp_exchange('physical_mode_query',b'qqemu.PhyMemMode')!=b'1':
                self._rsp_semantic('call_physical_mode','DENY')
            self._current_mode=_native(CurrentEpochMode,_registration=self._registration,_wire=self,
                stop=stop,operation_seq=self._operations[-1].seq,value=1)
            return self._current_mode

    def _require_after(self):
        deny(self._reads_complete is not None,'call_completion_pending')
        _root_guard(self,'_require_wire_after',self._reads_complete)

    def read_selected_registers(self,stop,phase):
        with self._epoch_attempt(stop):
            deny(type(phase) is str and phase in ('before','after'),'call_register_phase')
            deny(self._current_mode is not None and (phase=='before' and self._before_registers is None
                and self._host_lease is None or phase=='after' and self._before_registers is not None
                and self._host_receipt is not None and self._layout_before is not None
                and self._after_registers is None),'call_register_state')
            if phase=='after':self._require_after()
            from run0_c0_acquire import REGISTER_WIDTHS
            self._charge(29*128);values=[]
            for number,width in REGISTER_WIDTHS:
                self._charge(64)
                raw=self._rsp_exchange(f'p{number:x}',f'p{number:x}'.encode())
                if len(raw)!=2*width or rsp.HEX.fullmatch(raw) is None:
                    self._rsp_semantic('call_register_width','DENY')
                value=int.from_bytes(bytes.fromhex(raw.decode('ascii')),'little')
                values.append((number,width,value,self._operations[-1].seq))
            if phase=='before':
                address=self._breakpoint[0]
                if dict((n,v) for n,_,v,_ in values)[16]!=address:
                    self._rsp_semantic('call_stop_rip','DENY')
            elif tuple((n,w,v) for n,w,v,_ in values)!=tuple((n,w,v) for n,w,v,_ in self._before_registers.values):
                self._rsp_semantic('call_registers_changed','INCOMPLETE')
            receipt=_native(SelectedEpochRegisters,_registration=self._registration,_wire=self,
                stop=stop,phase=phase,values=tuple(values))
            if phase=='before':self._before_registers=receipt
            else:self._after_registers=receipt
            return receipt

    def begin_host_observation(self,stop,before_registers):
        with self._epoch_attempt(stop):
            deny(type(before_registers) is SelectedEpochRegisters and before_registers is self._before_registers
                and before_registers.stop is stop and self._current_mode is not None
                and self._host_lease is None,'call_host_lease_state')
            started=time.monotonic_ns();deadline=min(started+RESPONSE_NS,self._limit())
            self._charge(FRAME_CREDIT)
            # Held before quiet; any interruption cannot issue a renewed lease.
            self._host_lease=_native(ParentHostLease,_registration=self._registration,_wire=self,
                stop=stop,before_registers=before_registers,started_ns=started,deadline_ns=deadline)
            self._quiet(deadline);return self._host_lease

    def _lease(self,lease):
        self._current_stop(self._stop)
        deny(type(lease) is ParentHostLease and lease is self._host_lease
            and lease._registration is self._registration and lease._wire is self
            and lease.stop is self._stop and lease.before_registers is self._before_registers
            and self._host_receipt is None,'call_host_lease_state')
        self._time_left(lease.deadline_ns,'witness_deadline')

    def host_peer_credentials(self,lease):
        with self._epoch_attempt(self._stop):
            self._lease(lease)
            deny(self._host_peer is None and self._host_before is None,'call_host_peer_state')
            self._quiet(lease.deadline_ns)
            from run0_host_cpu_witness import NATIVE_LAYOUT
            self._charge(12+FRAME_CREDIT)
            raw=self._qmp.getsockopt(socket.SOL_SOCKET,NATIVE_LAYOUT['so_peercred'],12)
            observed=time.monotonic_ns();self._time_left(lease.deadline_ns,'witness_deadline')
            deny(type(raw) is bytes and len(raw)==12,'peer_credentials_shape')
            self._host_peer=_native(ParentPeerReceipt,_registration=self._registration,_wire=self,
                lease=lease,raw_bytes=raw,observed_ns=observed)
            return self._host_peer

    def _hmp_state(self,raw,registers):
        from run0_host_cpu_witness import c0_registers
        import run0_c0_decode as decoder
        deny(type(raw) is str and raw.isascii() and 0<len(raw)<=65536,'hmp_shape')
        # ASCII copy plus closed parsed state/regex working copies, independently
        # charged from wire frame decoding and retained raw streams.
        self._charge(8*len(raw)+4096)
        values={number:value for number,_,value,_ in registers.values}
        c0_registers(raw,values)
        try:parsed=decoder._hmp(raw.encode('ascii'),values)
        except decoder.C0DecodeError as error:raise ProbeError(error.status,error.reason) from error
        return (parsed['cpl'],parsed['smm'],parsed['a20'],parsed['cs64'],tuple(sorted(parsed['descriptors'].items())))

    def host_bracket(self,lease,phase):
        with self._epoch_attempt(self._stop):
            self._lease(lease)
            deny(type(phase) is str and (phase=='before' and self._host_peer is not None
                and self._host_before is None or phase=='after' and self._host_before is not None
                and self._host_after is None),'call_host_bracket_state')
            from run0_host_cpu_witness import cpu_path,realized_width,MAX_PID
            self._charge(2048);indices=[]
            def request(command,name,key,arguments=None):
                value,_=self._qmp_exchange(command,name,arguments,lease.deadline_ns,debug=command=='query-status')
                indices.append((key,self._operations[-1].seq));return value
            try:
                request('query-status','query_status','status_seq')
                cpus=request('query-cpus-fast','query_cpus_fast','cpu_seq');path=cpu_path(cpus);tid=cpus[0]['thread-id']
                deny(type(tid) is int and 1<=tid<=MAX_PID,'qmp_host_tid')
                realized=request('qom-get','qom_realized','realized_seq',{'path':path,'property':'realized'})
                width=request('qom-get','qom_phys_bits','phys_bits_seq',{'path':path,'property':'phys-bits'})
                width=realized_width(realized,width)
                raw=request('human-monitor-command','hmp_registers','hmp_seq',{'command-line':'info registers'})
                parsed=self._hmp_state(raw,self._before_registers);self._quiet(lease.deadline_ns)
                self._charge(len(raw));encoded=raw.encode('ascii')
                result=_native(ParentHostBracket,_registration=self._registration,_wire=self,lease=lease,
                    phase=phase,operations=tuple(indices),cpu_identity=(path,tid,width),hmp_bytes=encoded,parsed_state=parsed)
                if phase=='before':self._host_before=result
                else:
                    incomplete((result.cpu_identity,result.hmp_bytes,result.parsed_state)==
                        (self._host_before.cpu_identity,self._host_before.hmp_bytes,self._host_before.parsed_state),
                        'call_host_bracket_changed')
                    self._host_after=result
                return result
            except ProbeError:
                if indices and self._operations[-1].result=='ok':self._operations[-1]=replace(self._operations[-1],result='error')
                raise

    def pump_host_observation(self,lease):
        with self._epoch_attempt(self._stop):
            self._lease(lease);self._quiet(lease.deadline_ns)
            deny(self._frame_start==len(self._raw['qmp-in']),'qmp_observation_partial')

    def finish_host_observation(self,lease,actual_receipt):
        with self._epoch_attempt(self._stop):
            self._lease(lease)
            try:
                from run0_call_host import _issued_parent_observation
            except ImportError as error:raise ProbeError('INCOMPLETE','call_host_issuer_pending') from error
            deny(self._host_after is not None and _issued_parent_observation(actual_receipt,self,lease),
                'call_host_receipt_identity')
            self.pump_host_observation(lease);self._host_receipt=actual_receipt

    def read_final_register_view(self,stop,after_registers):
        with self._epoch_attempt(stop):
            deny(type(after_registers) is SelectedEpochRegisters and after_registers is self._after_registers
                and self._final_register_view is None,'call_final_register_state')
            self._require_after()
            raw,_=self._qmp_exchange('human-monitor-command','hmp_registers',{'command-line':'info registers'},self._limit())
            try:
                parsed=self._hmp_state(raw,after_registers);self._charge(len(raw));encoded=raw.encode('ascii')
                incomplete(encoded==self._host_before.hmp_bytes,'call_final_hmp_changed');self._quiet(self._limit())
                row=self._operations[-1]
                self._final_register_view=_native(EpochRegisterView,_registration=self._registration,_wire=self,
                    stop=stop,registers=after_registers,operation_seq=row.seq,wire=row.response,raw_bytes=encoded,parsed_state=parsed)
                return self._final_register_view
            except ProbeError:
                self._operations[-1]=replace(self._operations[-1],result='error');raise

    def read_current_layout(self,stop,phase):
        with self._epoch_attempt(stop):
            deny(type(phase) is str and (phase=='before' and self._host_receipt is not None
                and self._layout_before is None or phase=='after' and self._layout_before is not None
                and self._final_register_view is not None and self._layout_after is None),'call_layout_state')
            if phase=='after':self._require_after()
            raw,_=self._qmp_exchange('human-monitor-command','hmp_flatview',{'command-line':'info mtree -f'},self._limit())
            import run0_c0_decode as decoder
            from run0_rsp_capability import validate_profile_layout
            from boot_profile_capture import VAPIC_OFF_INVOCATION_PROFILE
            try:
                deny(type(raw) is str and raw.isascii() and 0<len(raw)<=65536,'layout_shape')
                self._charge(12*len(raw)+4096);encoded=raw.encode('ascii');ranges=decoder._layout(encoded)
                deny(ranges==validate_profile_layout(raw,VAPIC_OFF_INVOCATION_PROFILE),'call_layout_profile')
                if phase=='after':incomplete(encoded==self._layout_before.raw_bytes,'call_layout_changed')
                self._quiet(self._limit());row=self._operations[-1]
                result=_native(EpochLayoutReceipt,_registration=self._registration,_wire=self,stop=stop,phase=phase,
                    operation_seq=row.seq,wire=row.response,raw_bytes=encoded,ranges=tuple(ranges))
                if phase=='before':self._layout_before=result
                else:self._layout_after=result
                return result
            except (ProbeError,decoder.C0DecodeError) as error:
                self._operations[-1]=replace(self._operations[-1],result='error')
                raise ProbeError(error.status,error.reason) from error

    def bind_acquisition(self,registered_binding,session):
        with self._epoch_attempt(self._stop):
            _root_guard(self,'_require_wire_binding',registered_binding,session)
            from run0_call_capture import RegisteredCurrentEpochBinding
            deny(type(registered_binding) is RegisteredCurrentEpochBinding
                and registered_binding.registration is self._registration
                and registered_binding.session is session and session is not None
                and registered_binding.host_receipt is self._host_receipt and self._host_receipt is not None
                and registered_binding.layout_receipt is self._layout_before and self._layout_before is not None
                and self._registered_binding is None and self._session is None,'call_binding_identity')
            self._registered_binding=registered_binding;self._session=session

    def read_physical(self,grant):
        with self._epoch_attempt(self._stop):
            deny(self._registered_binding is not None and self._session is not None
                and self._reads_complete is None and self._active_pending is None,'call_read_state')
            _root_guard(self,'_require_wire_binding',self._registered_binding,self._session)
            return self._physical(grant)

    def _physical(self,grant):
        # Row allocation is not admission. Root prepare alone claims the one
        # existing ledger read; reserve_operation('m') would double-charge it.
        incomplete(self._rsp_acks<=MAX_RSP_ACKS-2,'rsp_ack_limit')
        index,row=self._new_operation('rsp','physical_read',physical=True)
        offset=len(self._raw['rsp-out']);request=None;response=None;result='error';finished=None
        pending=None;attempt=None;proof=None
        deadline=min(row.started_ns+RESPONSE_NS,self._limit())
        try:
            pending=_root_guard(self,'_prepare_wire_read',grant,operation_seq=row.seq)
            deny(type(pending) is PendingReadRetention and pending.key.operation_seq==row.seq
                and pending.key.epoch==self._epoch,'call_prepared_read_identity')
            self._active_pending=pending;self._physical_start=len(self._raw['rsp']);self._physical_frames=0
            # Additional prepaid wire envelope only. Ordinary read8L+2048 and
            # independent retainer verification/file/assembly credits untouched.
            self._charge(512+26*FRAME_CREDIT+512)
            target=pending.target;request=rsp.encode_packet(f'm{target.gpa:x},{target.length:x}'.encode())
            deny(len(request)<=25,'call_physical_request_bound')
            self._quiet(deadline)
            attempt=_root_guard(self,'_commit_wire_read',grant,pending)
            deny(type(attempt) is _HeldReadAttempt and self._read_attempts.get(row.seq) is attempt
                and attempt._parent is self._registration.parent_identity and attempt._wire is self
                and attempt.key==pending.key and attempt.target==target and attempt.started_ns==row.started_ns
                and attempt.finished_ns is None and attempt.result=='pending','call_read_attempt_identity')
            self._active_attempt=attempt
            self._send(request,deadline,protocol='rsp',attempt=attempt)
            ack,ackpos,_=self._next_rsp(deadline)
            rsp.require(ack.kind=='ACK','rsp_request_ack',status='INCOMPLETE' if ack.kind=='NACK' else 'DENY')
            packet,pos,observed=self._next_rsp(deadline);response=pos
            deny(packet.kind=='PACKET' and len(packet.raw)==2*target.length+4
                and len(packet.payload)==2*target.length and rsp.HEX.fullmatch(packet.payload) is not None,
                'call_physical_response')
            # Hex is unescaped; this view compares without creating another2L copy.
            deny(memoryview(packet.raw)[1:-3]==packet.payload,'call_physical_escaped_hex')
            self._quiet(deadline);_root_guard(self,'_recheck_wire_read',attempt)
            incomplete(self._rsp_acks<MAX_RSP_ACKS,'rsp_ack_limit');ackoffset=len(self._raw['rsp-out'])
            self._send(b'+',deadline,protocol='rsp',attempt=attempt);self._rsp_acks+=1
            self._time_left(deadline,'rsp_response_timeout');_root_guard(self,'_recheck_wire_read',attempt)
            ackfinished=time.monotonic_ns()
            object.__setattr__(attempt,'finished_ns',ackfinished);object.__setattr__(attempt,'result','ok')
            proof=_native(_HeldReadOperation,_parent=self._registration.parent_identity,_wire=self,
                attempt=attempt,key=pending.key,target=target,
                request_position=LiveWirePosition('rsp-out',offset,len(request)),
                request_ack_position=LiveWirePosition('rsp',ackpos.offset,ackpos.length),
                response_position=LiveWirePosition('rsp',pos.offset,pos.length),
                response_ack_position=LiveWirePosition('rsp-out',ackoffset,1),
                started_ns=row.started_ns,response_received_ns=observed,ack_finished_ns=ackfinished,result='ok')
            deny(row.seq not in self._read_operations,'call_read_operation_reused')
            self._read_operations[row.seq]=proof
            receipt=_root_guard(self,'_seal_wire_read',pending,proof,request_bytes=request,response_bytes=packet.raw)
            from run0_call_read import NativePhysicalReadReceipt
            deny(type(receipt) is NativePhysicalReadReceipt and receipt.parent is self._registration.parent_identity
                and receipt.session is self._session and receipt.operation_seq==row.seq
                and receipt.physical_ordinal==pending.key.physical_ordinal and receipt.result=='ok',
                'call_read_sealed_identity')
            self._time_left(deadline,'rsp_response_timeout')
            finished=receipt.finished_ns;result='ok';return receipt
        except ProbeError as error:
            if 'timeout' in error.reason or 'deadline' in error.reason:result='timeout'
            raise
        finally:
            # Root commit may have published its single shared pointer and then
            # been interrupted before return. Retain that admitted zero-byte fact.
            held=self._read_attempts.get(row.seq)
            if type(held) is _HeldReadAttempt and held._wire is self and held.result=='pending':
                object.__setattr__(held,'finished_ns',time.monotonic_ns());object.__setattr__(held,'result',result)
            self._finish_operation(index,row,offset,0 if request is None else len(request),response,result,finished)
            self._active_pending=self._active_attempt=None;self._physical_start=None

    def complete_phase(self,reads_complete):
        with self._epoch_attempt(self._stop):
            deny(self._registered_binding is not None and self._session is not None
                and self._reads_complete is None and self._after_receipt is None,'call_completion_state')
            _root_guard(self,'_require_wire_after',reads_complete)
            self._reads_complete=reads_complete
            registers=self.read_selected_registers(self._stop,'after')
            hmp=self.read_final_register_view(self._stop,registers)
            layout=self.read_current_layout(self._stop,'after')
            self._charge(FRAME_CREDIT)
            self._after_receipt=_native(EpochAfterReceipt,_registration=self._registration,_wire=self,
                stop=self._stop,reads_complete=reads_complete,registers=registers,hmp=hmp,layout=layout)
            return self._after_receipt

    def _retire_stop_slots(self):
        # Root archives the exact closed source before authorizing transition.
        # These current pointers cannot confer authority on a successor stop.
        self._stop=self._current_mode=self._before_registers=self._after_registers=None
        self._host_lease=self._host_peer=self._host_before=self._host_after=self._host_receipt=None
        self._layout_before=self._layout_after=self._final_register_view=self._after_receipt=None
        self._registered_binding=self._session=self._reads_complete=None
        self._active_pending=self._active_attempt=None;self._physical_start=None

    def prepare_transition(self,closed,target):
        with self._attempt():
            _root_guard(self,'_require_wire_transition',closed,target)
            from run0_call_capture import BoundCallTarget
            deny(type(closed) is ClosedEpochReceipt and type(target) is BoundCallTarget
                and closed._wire is self and closed._epoch==self._epoch and closed._memory_revoked is True
                and target.registration is self._registration and target.closed is closed
                and target.source_epoch==self._epoch and self._epoch in ('C0','C1')
                and target.target_epoch==('C1' if self._epoch=='C0' else 'C2')
                and type(target.address) is int and 0<target.address<(1<<64)
                and self._state=='STOPPED' and self._breakpoint is not None,'call_transition_identity')
            self._transition_started_ns=time.monotonic_ns()
            self._transition_closed=closed;self._transition_target=target;self._state='TRANSITION_PREP'
            self._transition_clear=self._transition_set=None;self._transition_quiet_ns=None;self._ticket=None
            self._clear_breakpoint()
            self._transition_clear=self._operations[-1]
            self._charge(512);reply=self._rsp_exchange('hardware_breakpoint_set',f'Z1,{target.address:x},1'.encode())
            if reply!=b'OK':self._rsp_semantic('rsp_breakpoint_reply','DENY')
            self._transition_set=self._operations[-1]
            self._breakpoint=(target.address,self._transition_set.seq,target)
            self._quiet(min(self._transition_started_ns+RESPONSE_NS,self._limit()))
            self._transition_quiet_ns=time.monotonic_ns()
            ticket=_root_guard(self,'_issue_wire_transition',closed,target)
            deny(type(ticket) is TransitionAdmission and ticket._wire is self
                and ticket._owner is self._registration.transition_owner and ticket._policy is self._policy
                and ticket.source_epoch==self._epoch and ticket.target_epoch==target.target_epoch,
                'call_transition_ticket')
            self._ticket=ticket;return ticket

    def resume_to_next(self,ticket):
        with self._attempt():
            deny(type(ticket) is TransitionAdmission and ticket is self._ticket
                and self._state=='TRANSITION_PREP','call_resume_ticket')
            _root_guard(self,'_require_wire_resume',ticket)
            return self._start_flight(ticket.target_epoch,self._transition_target,self._transition_closed,ticket)

    def _clear_breakpoint(self):
        deny(self._breakpoint is not None,'call_breakpoint_clear_once')
        self._charge(512);address=self._breakpoint[0]
        reply=self._rsp_exchange('hardware_breakpoint_clear',f'z1,{address:x},1'.encode())
        if reply!=b'OK':self._rsp_semantic('rsp_breakpoint_reply','DENY')
        self._breakpoint=None

    def terminate_parent(self,closed):
        with self._attempt():
            _root_guard(self,'_require_wire_termination',closed)
            deny(type(closed) is ClosedEpochReceipt and closed._wire is self and closed._epoch=='C2'
                and closed._memory_revoked is True and self._epoch=='C2' and self._state=='STOPPED'
                and self._terminal_closed is None,'call_termination_identity')
            self._terminal_closed=closed;self._state='TERMINAL_CLEAR';self._clear_breakpoint()
            self._request_quit()
            return self._drain_terminal(self._policy.effective_hard_ns,failed=False)

    def _request_quit(self):
        self._dispatch_guard();deny(self._quit is None and self._greeted,'call_quit_once')
        self._quiet(self._limit())
        deny(not self._qmp_eof and not self._qmp_damaged and not self._frames
            and self._frame_start==len(self._raw['qmp-in']),'qmp_quit_ambiguous')
        self._charge(8192);identifier=self._qmp_identifier+1
        request=json.dumps({'execute':'quit','id':identifier},separators=(',',':')).encode('ascii')
        incomplete(len(self._raw['qmp-out'])+len(request)<=MAX_QMP_BYTES,'qmp_request_bound')
        index,row=self._new_operation('qmp','quit');self._qmp_identifier=identifier
        self._quit=row;self._quit_deadline=min(row.started_ns+RESPONSE_NS,self._limit())
        self._state='QUIT_DISPATCH';offset=len(self._raw['qmp-out']);response=None;result='error';finished=None
        try:
            self._send(request,self._quit_deadline,protocol='qmp')
            self._time_left(self._quit_deadline,'qmp_quit_timeout');self._state='QUIT_WAIT'
            reply,pos,observed=self._next_qmp(self._quit_deadline)
            deny(set(reply)=={'return','id'} and type(reply['id']) is int and reply['id']==identifier
                and type(reply['return']) is dict and reply['return']=={},'qmp_quit_reply')
            response=pos;finished=observed;result='ok';self._quit_reply=(pos,observed);self._state='DRAIN'
        finally:
            self._finish_operation(index,row,offset,len(request),response,result,finished)
            self._quit=self._operations[index]

    def _drain_terminal(self,deadline_ns,*,failed):
        deny(type(deadline_ns) is int,'call_drain_deadline')
        deadline=min(deadline_ns,self._policy.effective_hard_ns)
        while self._selector is not None and self._selector.get_map():
            self._poll(deadline,'call_drain_timeout',drain=True)
            if not failed:
                if self._failure is not None:raise ProbeError(self._failure.status,self._failure.reason)
                deny(not self._frames and not self._rsp_frames,'call_terminal_extra')
        if not failed:
            deny(self._quit_reply is not None and self._quit.result=='ok','call_quit_reply_missing')
            deny(self._frame_start==len(self._raw['qmp-in']) and not self._rsp_decoder.pending,
                'call_terminal_partial')
            deny(len(self._eofs)==6 and {r.stream for r in self._eofs}=={'qmp-in',*STREAMS},'call_terminal_eof')
        self._accounting.reserve_output(ROW_CREDIT)
        receipt=_native(ParentDrainReceipt,_registration=self._registration,_wire=self,closed=self._terminal_closed,
            quit_operation=self._quit,eofs=tuple(self._eofs),io_errors=tuple(self._io_errors),
            observed_ns=time.monotonic_ns(),failure=self._failure)
        if not failed:self._state='DONE'
        self._drain=receipt;return receipt

    def _poll_failed_owner(self):
        # One nonblocking, failure-only pump. No receipt, sends or new authority.
        _root_guard(self,'_require_wire_failure_drain')
        deny(self._failure is not None and not self._closed,'call_failure_drain_state')
        deadline=self._policy.effective_hard_ns
        self._time_left(deadline,'call_drain_timeout')
        self._failed_draining=True
        if self._selector is not None:
            self._poll(deadline,'call_drain_timeout',wait=False,drain=True)

    def _drain_failed_owner(self,deadline_ns):
        # Complete failure-only drain is permitted only after the writer's
        # actual wait, against the original hard deadline, never a poll slice.
        _root_guard(self,'_require_wire_failure_drain')
        deny(self._failure is not None and not self._closed,'call_failure_drain_state')
        owner=self._registration.qemu_owner
        deny(owner.reaped is True and owner.ownership_lost is False
             and type(owner.returncode) is int and owner.child.returncode==owner.returncode,
             'call_failure_drain_writer')
        deny(type(deadline_ns) is int and deadline_ns==self._policy.effective_hard_ns,
             'call_drain_deadline')
        self._failed_draining=True
        while self._selector is not None and self._selector.get_map():
            self._poll(deadline_ns,'call_drain_timeout',drain=True)
        incomplete(len(self._eofs)==6 and {r.stream for r in self._eofs}=={'qmp-in',*STREAMS},
                   'call_failure_drain_eof')
        return self._drain_terminal(deadline_ns,failed=True)


@dataclass(frozen=True,slots=True)
class ParentReset:
    target:rsp.TargetDescription
    registers:rsp.RegisterSnapshot
    physical_mode:int

class _ParentReset(rsp._ResetSequence):
    def __init__(self,wire):
        deny(type(wire) is CallWire,'call_reset_wire');super().__init__();self._wire=wire
    def _exchange(self,name,payload):
        self._require_state('new','supported','thread_first','thread_next','thread_current',
            'thread_general','thread_continue','target_read','described','registers','qemu_supported','physical_zero','physical_set')
        rsp.require(type(payload) is bytes and self._payload_allowed(name,payload),'rsp_forbidden_operation',terminal=False)
        return self._wire._rsp_exchange({'feature_target':'target_read','feature_core':'core_read'}.get(name,name),payload)
    def _semantic(self,condition,reason,*,status='DENY'):
        if not condition:self._state='failed';self._wire._rsp_semantic(reason,status)
    def prepare(self):
        self.query_supported();self.query_threads();self.select_thread();target=self.read_target_description()
        registers=self.read_reset_registers();self._semantic(registers.values[16]==0xfff0,'rsp_reset_rip')
        self.query_qemu_supported();self.query_physical_mode();self.enable_physical_mode()
        return ParentReset(target,registers,self.query_physical_mode())
