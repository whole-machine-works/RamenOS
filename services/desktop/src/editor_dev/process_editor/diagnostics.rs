//! Bounded descriptive records, never accepted as authority.
use super::*;
use sha2::{Digest, Sha256};
use std::sync::{Condvar, MutexGuard};
use std::time::Duration;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAssertionPoint {
    BeforeSnapshotCopy,
    HeldVerifiedBeforeExec,
    ForkOwnedBeforeExecRelease,
    BootstrapBeforeSend,
    InputReceivedBeforeAck,
    OfferMappedBeforeSeal,
    PairValidatedBeforeAdopt,
    CaptureBeforeAdopt,
    SupervisorBeforeSignal,
    SupervisorBeforeWait,
    SupervisorTerminalBeforeJoin,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAssertionOperation {
    Open,
    MemfdCreate,
    Fstat,
    Pread,
    Pwrite,
    Read,
    Write,
    Poll,
    Truncate,
    GetSeals,
    AddSeals,
    Mmap,
    Munmap,
    Fork,
    PidfdOpen,
    Execveat,
    Sendmsg,
    Recvmsg,
    Signal,
    Waitpid,
    Close,
    DuplicateFd,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    PeerCredentials,
    SupervisorStart,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    ParseAncillary,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAssertionOrigin {
    Native,
    InjectedBeforeSyscall,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    ParserStructural,
    InjectedBeforeOperation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAssertionDescriptorRole {
    Selected,
    TextState,
    Surface,
    Executable,
    Control,
    Barrier,
    Pidfd,
    ExecError,
    Stdout,
    Stderr,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAssertionDescriptorEvent {
    Offered,
    Returned,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAssertionMapping {
    None,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    SharedWritable,
    ReadOnly,
    Unmapped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAssertionDisposition {
    Held,
    Received,
    Closed,
    Quarantined,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAssertionDirection {
    ParentToChild,
    ChildToParent,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAssertionExecutableAction {
    ReplacePath,
    MutateOriginalInode,
    HeldWrite,
    HeldGrow,
    HeldShrink,
}
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ProcessAssertionOwners {
    pub data: u32,
    pub fixed: u32,
    pub combined: u32,
    pub maps: u32,
    pub children: u32,
    pub supervisors: u32,
    pub pending_inputs: u32,
    pub ordinary_queue: u32,
    pub reset_queue: u32,
    pub lifetime_objects: u64,
    pub lifetime_bytes: u64,
    pub lifetime_offers: u32,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProcessAssertionSyscall {
    pub operation: ProcessAssertionOperation,
    pub origin: ProcessAssertionOrigin,
    pub result: i64,
    pub errno: Option<i32>,
    pub sender: Option<(u32, u32, u32)>,
    pub msg_flags: u32,
    pub received_fds: u32,
    pub descriptor_id: Option<u64>,
    pub poll_revents: u32,
    pub ancillary: Vec<u8>,
    pub ancillary_descriptor_ids: Vec<u64>,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProcessAssertionDescriptor {
    pub role: ProcessAssertionDescriptorRole,
    pub descriptor_id: u64,
    pub device: u64,
    pub inode: u64,
    pub byte_len: u64,
    pub owner_process_id: Option<u32>,
    pub offer_id: Option<u64>,
    pub event: ProcessAssertionDescriptorEvent,
    pub mode: u32,
    pub seals: u32,
    pub mapping: ProcessAssertionMapping,
    pub disposition: ProcessAssertionDisposition,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProcessAssertionObject {
    pub descriptor_id: u64,
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProcessAssertionControl {
    pub direction: ProcessAssertionDirection,
    pub bytes: Vec<u8>,
    pub sender: Option<(u32, u32, u32)>,
    pub msg_flags: u32,
    pub received_fds: u32,
    pub sequence: u64,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProcessAssertionExecutable {
    pub registered_sha256: [u8; 32],
    pub held_sha256: [u8; 32],
    pub source_before_sha256: [u8; 32],
    pub source_after_sha256: [u8; 32],
    pub source_before_device: u64,
    pub source_before_inode: u64,
    pub source_after_device: u64,
    pub source_after_inode: u64,
    pub held_device: u64,
    pub held_inode: u64,
    pub executed_device: Option<u64>,
    pub executed_inode: Option<u64>,
    pub executed_sha256: Option<[u8; 32]>,
    pub held_mode: u32,
    pub held_seals: u32,
    pub checkpoint_sequence: u64,
    pub action: Option<ProcessAssertionExecutableAction>,
    pub source_header: Vec<u8>,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProcessAssertionSnapshot {
    pub document: Option<NativeEditorObservation>,
    pub app_pixels: Vec<u8>,
    pub composed_pixels: Vec<u8>,
    pub app_sha256: [u8; 32],
    pub composed_sha256: [u8; 32],
    pub focus_epoch: u64,
    pub service_epoch: u64,
    pub channel_generation: u64,
    pub publication_generation: u64,
    pub delivered_sequence: u64,
    pub acknowledged_sequence: u64,
    pub request_sequence: u64,
    pub offer_cursor: u64,
    pub pending_offer_id: Option<u64>,
    pub syscall_count: u64,
    pub control_count: u64,
    pub descriptor_count: u64,
    pub core_ordinary_queue: u32,
    pub core_reset_queue: u32,
    pub owner_confirm_request: Option<[u8; 88]>,
    pub owner_confirm_status: Option<Status>,
    pub frame_surface_id: Option<u64>,
    pub frame_surface_generation: Option<u64>,
    pub frame_surface_epoch: Option<u64>,
    pub frame_surface_live: Option<bool>,
    pub owners: ProcessAssertionOwners,
    pub adoption_status: Option<Status>,
    pub admitted_at: Option<Instant>,
    pub child_deadline: Option<Instant>,
    pub captured_at: Option<Instant>,
    pub save_deadline: Option<Instant>,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProcessAssertionCheckpoint {
    point: ProcessAssertionPoint,
    reached_at: Instant,
    sequence: u64,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl ProcessAssertionCheckpoint {
    pub fn point(&self) -> ProcessAssertionPoint {
        self.point
    }
    pub fn reached_at(&self) -> Instant {
        self.reached_at
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}
#[derive(Debug)]
pub struct ProcessAssertionScenario {
    id: &'static str,
}
static SCENARIOS: &[ProcessAssertionScenario] = &[
    ProcessAssertionScenario {
        id: "D01DefaultBinaryAbsent",
    },
    ProcessAssertionScenario {
        id: "D01DefaultParentApiAbsent",
    },
    ProcessAssertionScenario {
        id: "D01ChildGraphExcludesDesktopStore",
    },
    ProcessAssertionScenario {
        id: "D02WrongRegisteredDigest",
    },
    ProcessAssertionScenario {
        id: "D02SourceSymlink",
    },
    ProcessAssertionScenario {
        id: "D02SourceNonregular",
    },
    ProcessAssertionScenario {
        id: "D02ScriptExecutable",
    },
    ProcessAssertionScenario {
        id: "D02InvalidElf",
    },
    ProcessAssertionScenario {
        id: "D02PreSnapshotSourceReplacement",
    },
    ProcessAssertionScenario {
        id: "D02PostHeldPathReplacement",
    },
    ProcessAssertionScenario {
        id: "D02PostHeldInodeMutation",
    },
    ProcessAssertionScenario {
        id: "D02HeldWriteDenied",
    },
    ProcessAssertionScenario {
        id: "D02HeldGrowDenied",
    },
    ProcessAssertionScenario {
        id: "D02HeldShrinkDenied",
    },
    ProcessAssertionScenario {
        id: "D02MemfdUnavailable",
    },
    ProcessAssertionScenario {
        id: "D02ExecveatUnavailable",
    },
    ProcessAssertionScenario {
        id: "D02BirthInstallFailure",
    },
    ProcessAssertionScenario {
        id: "D02PidfdInstallFailure",
    },
    ProcessAssertionScenario {
        id: "D02SupervisorInstallFailure",
    },
    ProcessAssertionScenario {
        id: "D03Frame87Bytes",
    },
    ProcessAssertionScenario {
        id: "D03Frame89Bytes",
    },
    ProcessAssertionScenario {
        id: "D03ProtocolZero",
    },
    ProcessAssertionScenario {
        id: "D03ForeignProtocolVersion",
    },
    ProcessAssertionScenario {
        id: "D03MessageTypeZero",
    },
    ProcessAssertionScenario {
        id: "D03MessageTypeNine",
    },
    ProcessAssertionScenario {
        id: "D03NonzeroTail84",
    },
    ProcessAssertionScenario {
        id: "D03NonzeroTail85",
    },
    ProcessAssertionScenario {
        id: "D03NonzeroTail86",
    },
    ProcessAssertionScenario {
        id: "D03NonzeroTail87",
    },
    ProcessAssertionScenario {
        id: "D03WrongPayloadLength",
    },
    ProcessAssertionScenario {
        id: "D03NonzeroReservedField",
    },
    ProcessAssertionScenario {
        id: "D03UnknownFlags",
    },
    ProcessAssertionScenario {
        id: "D03WrongMessageDirection",
    },
    ProcessAssertionScenario {
        id: "D04ForgedPidKernelReject",
    },
    ProcessAssertionScenario {
        id: "D04ForgedUidKernelReject",
    },
    ProcessAssertionScenario {
        id: "D04ForgedGidKernelReject",
    },
    ProcessAssertionScenario {
        id: "D04InheritedEndpointForeignPid",
    },
    ProcessAssertionScenario {
        id: "D04MissingCredentials",
    },
    ProcessAssertionScenario {
        id: "D04DuplicateCredentials",
    },
    ProcessAssertionScenario {
        id: "D04CreationPeercredIsNotSender",
    },
    ProcessAssertionScenario {
        id: "D04CopiedBootstrapPidActor",
    },
    ProcessAssertionScenario {
        id: "D05BootstrapFdZero",
    },
    ProcessAssertionScenario {
        id: "D05BootstrapFdOne",
    },
    ProcessAssertionScenario {
        id: "D05BootstrapFdTwo",
    },
    ProcessAssertionScenario {
        id: "D05BootstrapFdFour",
    },
    ProcessAssertionScenario {
        id: "D05DeliverInputFdOne",
    },
    ProcessAssertionScenario {
        id: "D05RequestPublicationFdZero",
    },
    ProcessAssertionScenario {
        id: "D05RequestPublicationFdOne",
    },
    ProcessAssertionScenario {
        id: "D05RequestPublicationFdThree",
    },
    ProcessAssertionScenario {
        id: "D05PublishFdZero",
    },
    ProcessAssertionScenario {
        id: "D05PublishFdOne",
    },
    ProcessAssertionScenario {
        id: "D05PublishFdThree",
    },
    ProcessAssertionScenario {
        id: "D05InputAckFdOne",
    },
    ProcessAssertionScenario { id: "D05StopFdOne" },
    ProcessAssertionScenario {
        id: "D05PublishAckFdOne",
    },
    ProcessAssertionScenario {
        id: "D05ReceiptNoticeFdOne",
    },
    ProcessAssertionScenario {
        id: "D05UnknownAncillary",
    },
    ProcessAssertionScenario {
        id: "D05DuplicateRights",
    },
    ProcessAssertionScenario {
        id: "D05AncillaryTruncation",
    },
    ProcessAssertionScenario {
        id: "D05RecordTruncation",
    },
    ProcessAssertionScenario {
        id: "D06SelectedHashMismatch",
    },
    ProcessAssertionScenario {
        id: "D06SelectedRevisionMismatch",
    },
    ProcessAssertionScenario {
        id: "D06SelectedObjectMismatch",
    },
    ProcessAssertionScenario {
        id: "D06SelectedInputUnsealed",
    },
    ProcessAssertionScenario {
        id: "D06FocusBeforeFirstFrame",
    },
    ProcessAssertionScenario {
        id: "D07ObserverOnlyChildOracleReject",
    },
    ProcessAssertionScenario {
        id: "D07ParentEditedDraftSourceReject",
    },
    ProcessAssertionScenario {
        id: "D07ParentRasterWithReportedPidSourceReject",
    },
    ProcessAssertionScenario { id: "D08Body4097" },
    ProcessAssertionScenario {
        id: "D08BodyNonAscii",
    },
    ProcessAssertionScenario { id: "D08BodyNul" },
    ProcessAssertionScenario {
        id: "D08UnsupportedKeyUsage",
    },
    ProcessAssertionScenario {
        id: "D08ContradictoryModifiers",
    },
    ProcessAssertionScenario {
        id: "D08InvalidKeyPhase",
    },
    ProcessAssertionScenario {
        id: "D09CursorBeyondBody",
    },
    ProcessAssertionScenario {
        id: "D09HalfSelectionSentinel",
    },
    ProcessAssertionScenario {
        id: "D09SelectionReversed",
    },
    ProcessAssertionScenario {
        id: "D09SelectionBeyondBody",
    },
    ProcessAssertionScenario {
        id: "D09FirstLineBeyondInventory",
    },
    ProcessAssertionScenario {
        id: "D09WrongViewGeneration",
    },
    ProcessAssertionScenario {
        id: "D10OversizedSurface",
    },
    ProcessAssertionScenario {
        id: "D10ProtectedChromeObjectAsSurface",
    },
    ProcessAssertionScenario {
        id: "D10ReservedKeyForwardingReject",
    },
    ProcessAssertionScenario {
        id: "D10ChildSavedImitationClipped",
    },
    ProcessAssertionScenario {
        id: "D11RetainedWritableMapping",
    },
    ProcessAssertionScenario {
        id: "D11FutureWriteOnly",
    },
    ProcessAssertionScenario {
        id: "D11MprotectOnly",
    },
    ProcessAssertionScenario {
        id: "D11MissingGrowSeal",
    },
    ProcessAssertionScenario {
        id: "D11MissingShrinkSeal",
    },
    ProcessAssertionScenario {
        id: "D11MissingFinalSeal",
    },
    ProcessAssertionScenario {
        id: "D11WriteAfterSeal",
    },
    ProcessAssertionScenario {
        id: "D11GrowAfterSeal",
    },
    ProcessAssertionScenario {
        id: "D11ShrinkAfterSeal",
    },
    ProcessAssertionScenario {
        id: "D12ForeignChildText",
    },
    ProcessAssertionScenario {
        id: "D12ForeignChildSurface",
    },
    ProcessAssertionScenario {
        id: "D12SwappedOfferedRoles",
    },
    ProcessAssertionScenario {
        id: "D12DuplicateOfferedFdRoles",
    },
    ProcessAssertionScenario {
        id: "D12EqualBytesForeignInode",
    },
    ProcessAssertionScenario {
        id: "D12StaleOfferId",
    },
    ProcessAssertionScenario {
        id: "D13TextLength127",
    },
    ProcessAssertionScenario {
        id: "D13TextLength4225",
    },
    ProcessAssertionScenario {
        id: "D13ControlLengthVsFstat",
    },
    ProcessAssertionScenario {
        id: "D13SurfaceLength1228799",
    },
    ProcessAssertionScenario {
        id: "D13SurfaceLength1228801",
    },
    ProcessAssertionScenario {
        id: "D13TextHeaderVersion",
    },
    ProcessAssertionScenario {
        id: "D13TextHeaderReserved",
    },
    ProcessAssertionScenario {
        id: "D13TextBodyHash",
    },
    ProcessAssertionScenario {
        id: "D13BaseRevisionMismatch",
    },
    ProcessAssertionScenario {
        id: "D13TextObjectMismatch",
    },
    ProcessAssertionScenario {
        id: "D13StateControlGenerationMismatch",
    },
    ProcessAssertionScenario {
        id: "D13SurfaceCompanionHashMismatch",
    },
    ProcessAssertionScenario {
        id: "D13SurfaceAlphaMismatch",
    },
    ProcessAssertionScenario {
        id: "D13SurfaceFormatMismatch",
    },
    ProcessAssertionScenario {
        id: "D14OldRequest",
    },
    ProcessAssertionScenario {
        id: "D14FutureInput",
    },
    ProcessAssertionScenario {
        id: "D14DuplicatePublish",
    },
    ProcessAssertionScenario {
        id: "D14DuplicateAck",
    },
    ProcessAssertionScenario {
        id: "D14WrongChannelGeneration",
    },
    ProcessAssertionScenario {
        id: "D14OldFocusEpoch",
    },
    ProcessAssertionScenario {
        id: "D14OldServiceEpoch",
    },
    ProcessAssertionScenario {
        id: "D14ForeignDocumentBinding",
    },
    ProcessAssertionScenario {
        id: "D14RequestCounterMax",
    },
    ProcessAssertionScenario {
        id: "D14PublicationCounterMax",
    },
    ProcessAssertionScenario {
        id: "D14TextCounterMax",
    },
    ProcessAssertionScenario {
        id: "D14ViewCounterMax",
    },
    ProcessAssertionScenario {
        id: "D14ChannelCounterMax",
    },
    ProcessAssertionScenario {
        id: "D15DataOwnerThirteen",
    },
    ProcessAssertionScenario {
        id: "D15FixedOwnerSeventeen",
    },
    ProcessAssertionScenario {
        id: "D15CombinedOwnerTwentyNine",
    },
    ProcessAssertionScenario {
        id: "D15PendingInputTwo",
    },
    ProcessAssertionScenario {
        id: "D15OrdinaryQueueSixtyFive",
    },
    ProcessAssertionScenario {
        id: "D15ReservedResetTwo",
    },
    ProcessAssertionScenario {
        id: "D15TotalQueueSixtySix",
    },
    ProcessAssertionScenario {
        id: "D15InflightSaveTwo",
    },
    ProcessAssertionScenario {
        id: "D15LiveEditorThree",
    },
    ProcessAssertionScenario {
        id: "D15SupervisorThree",
    },
    ProcessAssertionScenario {
        id: "D15StoreDataThirtyThree",
    },
    ProcessAssertionScenario {
        id: "D15StorePinSeventeen",
    },
    ProcessAssertionScenario {
        id: "D15StorePendingSeventeen",
    },
    ProcessAssertionScenario {
        id: "D15StoreQuerySixtyFive",
    },
    ProcessAssertionScenario {
        id: "D15StoreProducerSixtyFive",
    },
    ProcessAssertionScenario {
        id: "D15StoreIoThree",
    },
    ProcessAssertionScenario {
        id: "D16LifetimeOffer129",
    },
    ProcessAssertionScenario {
        id: "D16LifetimeObject258",
    },
    ProcessAssertionScenario {
        id: "D16LifetimeByteCapPlusOne",
    },
    ProcessAssertionScenario {
        id: "D16ExistingInodeAsNewCredit",
    },
    ProcessAssertionScenario {
        id: "D16DropDoesNotRefund",
    },
    ProcessAssertionScenario {
        id: "D16ReseedDoesNotRefund",
    },
    ProcessAssertionScenario {
        id: "D16CounterResetDoesNotRefund",
    },
    ProcessAssertionScenario {
        id: "D17ShortReceipt",
    },
    ProcessAssertionScenario {
        id: "D17ForeignReceiptBinding",
    },
    ProcessAssertionScenario {
        id: "D17ReceiptHashMismatch",
    },
    ProcessAssertionScenario {
        id: "D17ReceiptRevisionMismatch",
    },
    ProcessAssertionScenario {
        id: "D17ChildReceiptSetterApiAbsent",
    },
    ProcessAssertionScenario {
        id: "D17CopiedAllocationClaim",
    },
    ProcessAssertionScenario {
        id: "D18OrdinaryPublishSaveClaim",
    },
    ProcessAssertionScenario {
        id: "D18UnsolicitedCapture",
    },
    ProcessAssertionScenario {
        id: "D18CopiedOldCaptureRequest",
    },
    ProcessAssertionScenario {
        id: "D18CaptureConsumedTwice",
    },
    ProcessAssertionScenario {
        id: "D18CaptureAfter1000Ms",
    },
    ProcessAssertionScenario {
        id: "D18RoundTripCannotRenewCapture",
    },
    ProcessAssertionScenario {
        id: "D19RepeatSaveWhileSaving",
    },
    ProcessAssertionScenario {
        id: "D19RepeatSaveWhileUnknown",
    },
    ProcessAssertionScenario {
        id: "D19OldReceiptNewDraftUnsaved",
    },
    ProcessAssertionScenario {
        id: "D20OrdinaryRetiredLookupDenied",
    },
    ProcessAssertionScenario {
        id: "D20ForeignOriginalOwnerDenied",
    },
    ProcessAssertionScenario {
        id: "D20NewIntentCannotReconcileOld",
    },
    ProcessAssertionScenario {
        id: "D20OriginalAllocationCountPreserved",
    },
    ProcessAssertionScenario {
        id: "D21DeathBeforeCapture",
    },
    ProcessAssertionScenario {
        id: "D21DeathAfterAllocateBeforePermit",
    },
    ProcessAssertionScenario {
        id: "D21PublicationAfterDeath",
    },
    ProcessAssertionScenario {
        id: "D22DropChildDoesNotDropWriter",
    },
    ProcessAssertionScenario {
        id: "D22SignalRequestIsNotReap",
    },
    ProcessAssertionScenario {
        id: "D22ChildReapIsNotStoreJoin",
    },
    ProcessAssertionScenario {
        id: "D22NoOrdinaryGrantRevival",
    },
    ProcessAssertionScenario {
        id: "D23OldPreviewEnterDenied",
    },
    ProcessAssertionScenario {
        id: "D23OldBootstrapDenied",
    },
    ProcessAssertionScenario {
        id: "D23NoAutomaticRespawn",
    },
    ProcessAssertionScenario {
        id: "D23UnknownCannotChooseOldOrNewBase",
    },
    ProcessAssertionScenario {
        id: "D24NoRegistryLockAcrossReceive",
    },
    ProcessAssertionScenario {
        id: "D24NoRegistryLockAcrossSignalWait",
    },
    ProcessAssertionScenario {
        id: "D24WatchdogWithoutPump",
    },
    ProcessAssertionScenario {
        id: "D24OtherSessionCannotRenewDeadline",
    },
    ProcessAssertionScenario {
        id: "D25ScenarioControlRow32769",
    },
    ProcessAssertionScenario {
        id: "D25AggregateControlRow131073",
    },
    ProcessAssertionScenario {
        id: "D25StdoutCapPlusOne",
    },
    ProcessAssertionScenario {
        id: "D25StderrCapPlusOne",
    },
    ProcessAssertionScenario {
        id: "D25EofWithPendingOffer",
    },
    ProcessAssertionScenario {
        id: "D25ShortRecord",
    },
    ProcessAssertionScenario {
        id: "D25ActualSendBackpressure",
    },
    ProcessAssertionScenario {
        id: "D25ReceiveInterrupted",
    },
    ProcessAssertionScenario {
        id: "D25SendInterrupted",
    },
    ProcessAssertionScenario {
        id: "D26FrameAfterRevoke",
    },
    ProcessAssertionScenario {
        id: "D26CaptureAfterRevoke",
    },
    ProcessAssertionScenario {
        id: "D26OldGenerationCannotRevive",
    },
    ProcessAssertionScenario {
        id: "D26IssuedPermitCannotCancel",
    },
    ProcessAssertionScenario {
        id: "D27OrdinaryOverflowReservedReset",
    },
    ProcessAssertionScenario {
        id: "D27OldKeyPressRelease",
    },
    ProcessAssertionScenario {
        id: "D27OldResetServiceEpoch",
    },
    ProcessAssertionScenario {
        id: "D27OldSurfaceGeneration",
    },
    ProcessAssertionScenario {
        id: "D27StaleResetCapture",
    },
    ProcessAssertionScenario {
        id: "D28BudgetZero",
    },
    ProcessAssertionScenario {
        id: "D28Budget5001",
    },
    ProcessAssertionScenario {
        id: "D28SpawnPauseCannotRenew",
    },
    ProcessAssertionScenario {
        id: "D28BootstrapPauseCannotRenew",
    },
    ProcessAssertionScenario {
        id: "D28RoundTripCannotRenew",
    },
    ProcessAssertionScenario {
        id: "D28IntentRequestCannotRenew",
    },
    ProcessAssertionScenario {
        id: "D28BackdatedCoreClock",
    },
    ProcessAssertionScenario {
        id: "D29WaitFailureRetainsOwner",
    },
    ProcessAssertionScenario {
        id: "D29SignalFailureRetainsOwner",
    },
    ProcessAssertionScenario {
        id: "D29PidfdReadyIsNotReap",
    },
    ProcessAssertionScenario {
        id: "D29EofIsNotReap",
    },
    ProcessAssertionScenario {
        id: "D29DropIsNotReap",
    },
    ProcessAssertionScenario {
        id: "D29ForeignNumericPidIsNotOwner",
    },
    ProcessAssertionScenario {
        id: "D29ThreadJoinIsNotReap",
    },
    ProcessAssertionScenario {
        id: "D29ConsumingJoinReturnsOwnerWithoutUnwind",
    },
    ProcessAssertionScenario {
        id: "D29LiveJoinNotReadyIsPrompt",
    },
    ProcessAssertionScenario {
        id: "D30OriginalOneSecondDeadlineUnchanged",
    },
    ProcessAssertionScenario {
        id: "D30NoFabricatedJoinFence",
    },
    ProcessAssertionScenario {
        id: "D30NoCachedPassAcceptance",
    },
    ProcessAssertionScenario {
        id: "D30ProtocolGrantInventoryUnchanged",
    },
    ProcessAssertionScenario {
        id: "D30StoreIoExcludedFromSchema",
    },
    ProcessAssertionScenario {
        id: "D30DesktopGraphExcludesStoreApp",
    },
    ProcessAssertionScenario {
        id: "D01ExplicitChildParentBuild",
    },
    ProcessAssertionScenario {
        id: "D02HeldRegisteredElfExecAndRealReap",
    },
    ProcessAssertionScenario {
        id: "D03AllEightCanonicalMessages",
    },
    ProcessAssertionScenario {
        id: "D04GenuineOwnedSender",
    },
    ProcessAssertionScenario {
        id: "D05ExactDescriptorRolesAndFreshCarrier",
    },
    ProcessAssertionScenario {
        id: "D06GenuineReadFirstFrameThenFocus",
    },
    ProcessAssertionScenario {
        id: "D07ActualChildEditAndRasterGolden",
    },
    ProcessAssertionScenario {
        id: "D08EmptyBase4096PressReleaseAndCtrlS",
    },
    ProcessAssertionScenario {
        id: "D09FrozenCursorSelectionScrollGolden",
    },
    ProcessAssertionScenario {
        id: "D10ProtectedChromeAndOrdinaryChildKey",
    },
    ProcessAssertionScenario {
        id: "D11AllAliasesUnmappedFullSeals",
    },
    ProcessAssertionScenario {
        id: "D12ExactPendingOfferedPair",
    },
    ProcessAssertionScenario {
        id: "D13ExactCompleteTextStateAndSurface",
    },
    ProcessAssertionScenario {
        id: "D14CurrentAcknowledgmentAndPublication",
    },
    ProcessAssertionScenario {
        id: "D15RealOwnerReleaseThenAdmit",
    },
    ProcessAssertionScenario {
        id: "D16LifetimeOffer128ThenFreshReapedChild",
    },
    ProcessAssertionScenario {
        id: "D17OneGenuineSaveReceiptAndFreshChildReopen",
    },
    ProcessAssertionScenario {
        id: "D18FreshSingleUseCtrlSCapture",
    },
    ProcessAssertionScenario {
        id: "D19OlderReceiptThenFreshAuthorizedSave",
    },
    ProcessAssertionScenario {
        id: "D20OriginalLookupThenFreshRestart",
    },
    ProcessAssertionScenario {
        id: "D21GenuineUnpermittedClosureThenApprovedChild",
    },
    ProcessAssertionScenario {
        id: "D22OriginalWriterSettlesAfterChildReap",
    },
    ProcessAssertionScenario {
        id: "D23FreshPreviewApprovalNewBirth",
    },
    ProcessAssertionScenario {
        id: "D24IndependentChildBWithinOneSecond",
    },
    ProcessAssertionScenario {
        id: "D25BoundedRetryThenFreshOwner",
    },
    ProcessAssertionScenario {
        id: "D26OtherOwnerAndOriginalReceiptProgress",
    },
    ProcessAssertionScenario {
        id: "D27FreshResetApprovalAndSurface",
    },
    ProcessAssertionScenario {
        id: "D28WithinOriginalBudgetAndActualExpiry",
    },
    ProcessAssertionScenario {
        id: "D29SoleWaitThenSupervisorJoinAndChargeRelease",
    },
    ProcessAssertionScenario {
        id: "D30AllUnchangedConsumersOnSameCandidate",
    },
];
impl ProcessAssertionScenario {
    pub fn id(&self) -> &'static str {
        self.id
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub fn for_case(case: &'static str) -> Result<&'static [Self], Status> {
        match case {
            "D01C01" => Ok(&SCENARIOS[0..1]),
            "D01C02" => Ok(&SCENARIOS[1..2]),
            "D01C03" => Ok(&SCENARIOS[2..3]),
            "D02C01" => Ok(&SCENARIOS[3..4]),
            "D02C02" => Ok(&SCENARIOS[4..6]),
            "D02C03" => Ok(&SCENARIOS[6..8]),
            "D02C04" => Ok(&SCENARIOS[8..9]),
            "D02C05" => Ok(&SCENARIOS[9..10]),
            "D02C06" => Ok(&SCENARIOS[10..11]),
            "D02C07" => Ok(&SCENARIOS[11..14]),
            "D02C08" => Ok(&SCENARIOS[14..16]),
            "D02C09" => Ok(&SCENARIOS[16..19]),
            "D03C01" => Ok(&SCENARIOS[19..20]),
            "D03C02" => Ok(&SCENARIOS[20..21]),
            "D03C03" => Ok(&SCENARIOS[21..22]),
            "D03C04" => Ok(&SCENARIOS[22..23]),
            "D03C05" => Ok(&SCENARIOS[23..24]),
            "D03C06" => Ok(&SCENARIOS[24..25]),
            "D03C07" => Ok(&SCENARIOS[25..29]),
            "D03C08" => Ok(&SCENARIOS[29..30]),
            "D03C09" => Ok(&SCENARIOS[30..31]),
            "D03C10" => Ok(&SCENARIOS[31..32]),
            "D03C11" => Ok(&SCENARIOS[32..33]),
            "D04C01" => Ok(&SCENARIOS[33..36]),
            "D04C02" => Ok(&SCENARIOS[36..37]),
            "D04C03" => Ok(&SCENARIOS[37..39]),
            "D04C04" => Ok(&SCENARIOS[39..40]),
            "D04C05" => Ok(&SCENARIOS[40..41]),
            "D05C01" => Ok(&SCENARIOS[41..45]),
            "D05C02" => Ok(&SCENARIOS[45..46]),
            "D05C03" => Ok(&SCENARIOS[46..49]),
            "D05C04" => Ok(&SCENARIOS[49..52]),
            "D05C05" => Ok(&SCENARIOS[52..56]),
            "D05C06" => Ok(&SCENARIOS[56..57]),
            "D05C07" => Ok(&SCENARIOS[57..58]),
            "D05C08" => Ok(&SCENARIOS[58..59]),
            "D05C09" => Ok(&SCENARIOS[59..60]),
            "D06C01" => Ok(&SCENARIOS[60..61]),
            "D06C02" => Ok(&SCENARIOS[61..62]),
            "D06C03" => Ok(&SCENARIOS[62..63]),
            "D06C04" => Ok(&SCENARIOS[63..64]),
            "D06C05" => Ok(&SCENARIOS[64..65]),
            "D07C01" => Ok(&SCENARIOS[65..66]),
            "D07C02" => Ok(&SCENARIOS[66..67]),
            "D07C03" => Ok(&SCENARIOS[67..68]),
            "D08C01" => Ok(&SCENARIOS[68..69]),
            "D08C02" => Ok(&SCENARIOS[69..70]),
            "D08C03" => Ok(&SCENARIOS[70..71]),
            "D08C04" => Ok(&SCENARIOS[71..72]),
            "D08C05" => Ok(&SCENARIOS[72..73]),
            "D08C06" => Ok(&SCENARIOS[73..74]),
            "D09C01" => Ok(&SCENARIOS[74..75]),
            "D09C02" => Ok(&SCENARIOS[75..76]),
            "D09C03" => Ok(&SCENARIOS[76..77]),
            "D09C04" => Ok(&SCENARIOS[77..78]),
            "D09C05" => Ok(&SCENARIOS[78..79]),
            "D09C06" => Ok(&SCENARIOS[79..80]),
            "D10C01" => Ok(&SCENARIOS[80..81]),
            "D10C02" => Ok(&SCENARIOS[81..82]),
            "D10C03" => Ok(&SCENARIOS[82..83]),
            "D10C04" => Ok(&SCENARIOS[83..84]),
            "D11C01" => Ok(&SCENARIOS[84..85]),
            "D11C02" => Ok(&SCENARIOS[85..86]),
            "D11C03" => Ok(&SCENARIOS[86..87]),
            "D11C04" => Ok(&SCENARIOS[87..88]),
            "D11C05" => Ok(&SCENARIOS[88..89]),
            "D11C06" => Ok(&SCENARIOS[89..90]),
            "D11C07" => Ok(&SCENARIOS[90..91]),
            "D11C08" => Ok(&SCENARIOS[91..92]),
            "D11C09" => Ok(&SCENARIOS[92..93]),
            "D12C01" => Ok(&SCENARIOS[93..94]),
            "D12C02" => Ok(&SCENARIOS[94..95]),
            "D12C03" => Ok(&SCENARIOS[95..96]),
            "D12C04" => Ok(&SCENARIOS[96..97]),
            "D12C05" => Ok(&SCENARIOS[97..98]),
            "D12C06" => Ok(&SCENARIOS[98..99]),
            "D13C01" => Ok(&SCENARIOS[99..100]),
            "D13C02" => Ok(&SCENARIOS[100..101]),
            "D13C03" => Ok(&SCENARIOS[101..102]),
            "D13C04" => Ok(&SCENARIOS[102..103]),
            "D13C05" => Ok(&SCENARIOS[103..104]),
            "D13C06" => Ok(&SCENARIOS[104..107]),
            "D13C07" => Ok(&SCENARIOS[107..109]),
            "D13C08" => Ok(&SCENARIOS[109..110]),
            "D13C09" => Ok(&SCENARIOS[110..111]),
            "D13C10" => Ok(&SCENARIOS[111..113]),
            "D14C01" => Ok(&SCENARIOS[113..114]),
            "D14C02" => Ok(&SCENARIOS[114..115]),
            "D14C03" => Ok(&SCENARIOS[115..116]),
            "D14C04" => Ok(&SCENARIOS[116..117]),
            "D14C05" => Ok(&SCENARIOS[117..118]),
            "D14C06" => Ok(&SCENARIOS[118..119]),
            "D14C07" => Ok(&SCENARIOS[119..120]),
            "D14C08" => Ok(&SCENARIOS[120..121]),
            "D14C09" => Ok(&SCENARIOS[121..126]),
            "D15C01" => Ok(&SCENARIOS[126..127]),
            "D15C02" => Ok(&SCENARIOS[127..128]),
            "D15C03" => Ok(&SCENARIOS[128..129]),
            "D15C04" => Ok(&SCENARIOS[129..130]),
            "D15C05" => Ok(&SCENARIOS[130..131]),
            "D15C06" => Ok(&SCENARIOS[131..132]),
            "D15C07" => Ok(&SCENARIOS[132..133]),
            "D15C08" => Ok(&SCENARIOS[133..134]),
            "D15C09" => Ok(&SCENARIOS[134..135]),
            "D15C10" => Ok(&SCENARIOS[135..136]),
            "D15C11" => Ok(&SCENARIOS[136..142]),
            "D16C01" => Ok(&SCENARIOS[142..143]),
            "D16C02" => Ok(&SCENARIOS[143..144]),
            "D16C03" => Ok(&SCENARIOS[144..145]),
            "D16C04" => Ok(&SCENARIOS[145..146]),
            "D16C05" => Ok(&SCENARIOS[146..149]),
            "D17C01" => Ok(&SCENARIOS[149..150]),
            "D17C02" => Ok(&SCENARIOS[150..153]),
            "D17C03" => Ok(&SCENARIOS[153..154]),
            "D17C04" => Ok(&SCENARIOS[154..155]),
            "D18C01" => Ok(&SCENARIOS[155..156]),
            "D18C02" => Ok(&SCENARIOS[156..157]),
            "D18C03" => Ok(&SCENARIOS[157..158]),
            "D18C04" => Ok(&SCENARIOS[158..159]),
            "D18C05" => Ok(&SCENARIOS[159..160]),
            "D18C06" => Ok(&SCENARIOS[160..161]),
            "D19C01" => Ok(&SCENARIOS[161..162]),
            "D19C02" => Ok(&SCENARIOS[162..163]),
            "D19C03" => Ok(&SCENARIOS[163..164]),
            "D20C01" => Ok(&SCENARIOS[164..165]),
            "D20C02" => Ok(&SCENARIOS[165..166]),
            "D20C03" => Ok(&SCENARIOS[166..167]),
            "D20C04" => Ok(&SCENARIOS[167..168]),
            "D21C01" => Ok(&SCENARIOS[168..169]),
            "D21C02" => Ok(&SCENARIOS[169..170]),
            "D21C03" => Ok(&SCENARIOS[170..171]),
            "D22C01" => Ok(&SCENARIOS[171..172]),
            "D22C02" => Ok(&SCENARIOS[172..173]),
            "D22C03" => Ok(&SCENARIOS[173..174]),
            "D22C04" => Ok(&SCENARIOS[174..175]),
            "D23C01" => Ok(&SCENARIOS[175..176]),
            "D23C02" => Ok(&SCENARIOS[176..177]),
            "D23C03" => Ok(&SCENARIOS[177..178]),
            "D23C04" => Ok(&SCENARIOS[178..179]),
            "D24C01" => Ok(&SCENARIOS[179..180]),
            "D24C02" => Ok(&SCENARIOS[180..181]),
            "D24C03" => Ok(&SCENARIOS[181..182]),
            "D24C04" => Ok(&SCENARIOS[182..183]),
            "D25C01" => Ok(&SCENARIOS[183..185]),
            "D25C02" => Ok(&SCENARIOS[185..186]),
            "D25C03" => Ok(&SCENARIOS[186..187]),
            "D25C04" => Ok(&SCENARIOS[187..188]),
            "D25C05" => Ok(&SCENARIOS[188..189]),
            "D25C06" => Ok(&SCENARIOS[189..190]),
            "D25C07" => Ok(&SCENARIOS[190..191]),
            "D25C08" => Ok(&SCENARIOS[191..192]),
            "D26C01" => Ok(&SCENARIOS[192..193]),
            "D26C02" => Ok(&SCENARIOS[193..194]),
            "D26C03" => Ok(&SCENARIOS[194..195]),
            "D26C04" => Ok(&SCENARIOS[195..196]),
            "D27C01" => Ok(&SCENARIOS[196..197]),
            "D27C02" => Ok(&SCENARIOS[197..198]),
            "D27C03" => Ok(&SCENARIOS[198..199]),
            "D27C04" => Ok(&SCENARIOS[199..200]),
            "D27C05" => Ok(&SCENARIOS[200..201]),
            "D28C01" => Ok(&SCENARIOS[201..202]),
            "D28C02" => Ok(&SCENARIOS[202..203]),
            "D28C03" => Ok(&SCENARIOS[203..204]),
            "D28C04" => Ok(&SCENARIOS[204..205]),
            "D28C05" => Ok(&SCENARIOS[205..206]),
            "D28C06" => Ok(&SCENARIOS[206..207]),
            "D28C07" => Ok(&SCENARIOS[207..208]),
            "D29C01" => Ok(&SCENARIOS[208..209]),
            "D29C02" => Ok(&SCENARIOS[209..210]),
            "D29C03" => Ok(&SCENARIOS[210..211]),
            "D29C04" => Ok(&SCENARIOS[211..212]),
            "D29C05" => Ok(&SCENARIOS[212..213]),
            "D29C06" => Ok(&SCENARIOS[213..214]),
            "D29C07" => Ok(&SCENARIOS[214..215]),
            "D29C08" => Ok(&SCENARIOS[215..216]),
            "D29C09" => Ok(&SCENARIOS[216..217]),
            "D30C01" => Ok(&SCENARIOS[217..218]),
            "D30C02" => Ok(&SCENARIOS[218..219]),
            "D30C03" => Ok(&SCENARIOS[219..220]),
            "D30C04" => Ok(&SCENARIOS[220..221]),
            "D30C05" => Ok(&SCENARIOS[221..222]),
            "D30C06" => Ok(&SCENARIOS[222..223]),
            "D01P" => Ok(&SCENARIOS[223..224]),
            "D02P" => Ok(&SCENARIOS[224..225]),
            "D03P" => Ok(&SCENARIOS[225..226]),
            "D04P" => Ok(&SCENARIOS[226..227]),
            "D05P" => Ok(&SCENARIOS[227..228]),
            "D06P" => Ok(&SCENARIOS[228..229]),
            "D07P" => Ok(&SCENARIOS[229..230]),
            "D08P" => Ok(&SCENARIOS[230..231]),
            "D09P" => Ok(&SCENARIOS[231..232]),
            "D10P" => Ok(&SCENARIOS[232..233]),
            "D11P" => Ok(&SCENARIOS[233..234]),
            "D12P" => Ok(&SCENARIOS[234..235]),
            "D13P" => Ok(&SCENARIOS[235..236]),
            "D14P" => Ok(&SCENARIOS[236..237]),
            "D15P" => Ok(&SCENARIOS[237..238]),
            "D16P" => Ok(&SCENARIOS[238..239]),
            "D17P" => Ok(&SCENARIOS[239..240]),
            "D18P" => Ok(&SCENARIOS[240..241]),
            "D19P" => Ok(&SCENARIOS[241..242]),
            "D20P" => Ok(&SCENARIOS[242..243]),
            "D21P" => Ok(&SCENARIOS[243..244]),
            "D22P" => Ok(&SCENARIOS[244..245]),
            "D23P" => Ok(&SCENARIOS[245..246]),
            "D24P" => Ok(&SCENARIOS[246..247]),
            "D25P" => Ok(&SCENARIOS[247..248]),
            "D26P" => Ok(&SCENARIOS[248..249]),
            "D27P" => Ok(&SCENARIOS[249..250]),
            "D28P" => Ok(&SCENARIOS[250..251]),
            "D29P" => Ok(&SCENARIOS[251..252]),
            "D30P" => Ok(&SCENARIOS[252..253]),
            _ => Err(Status::Invalid),
        }
    }
    pub(super) fn assertion_child(&self) -> bool {
        matches!(
            self.id,
            "D03ForeignProtocolVersion"
                | "D03Frame87Bytes"
                | "D03Frame89Bytes"
                | "D03MessageTypeNine"
                | "D03MessageTypeZero"
                | "D03NonzeroReservedField"
                | "D03NonzeroTail84"
                | "D03NonzeroTail85"
                | "D03NonzeroTail86"
                | "D03NonzeroTail87"
                | "D03ProtocolZero"
                | "D03UnknownFlags"
                | "D03WrongMessageDirection"
                | "D03WrongPayloadLength"
                | "D05InputAckFdOne"
                | "D05PublishFdOne"
                | "D05PublishFdThree"
                | "D05PublishFdZero"
                | "D05RecordTruncation"
                | "D07ObserverOnlyChildOracleReject"
                | "D08Body4097"
                | "D08BodyNonAscii"
                | "D08BodyNul"
                | "D09CursorBeyondBody"
                | "D09FirstLineBeyondInventory"
                | "D09HalfSelectionSentinel"
                | "D09SelectionBeyondBody"
                | "D09SelectionReversed"
                | "D09WrongViewGeneration"
                | "D10ChildSavedImitationClipped"
                | "D10OversizedSurface"
                | "D11FutureWriteOnly"
                | "D11MissingFinalSeal"
                | "D11MissingGrowSeal"
                | "D11MissingShrinkSeal"
                | "D11MprotectOnly"
                | "D11RetainedWritableMapping"
                | "D12DuplicateOfferedFdRoles"
                | "D12ForeignChildText"
                | "D12ForeignChildSurface"
                | "D12EqualBytesForeignInode"
                | "D12StaleOfferId"
                | "D12SwappedOfferedRoles"
                | "D13BaseRevisionMismatch"
                | "D13ControlLengthVsFstat"
                | "D13StateControlGenerationMismatch"
                | "D13SurfaceAlphaMismatch"
                | "D13SurfaceCompanionHashMismatch"
                | "D13SurfaceFormatMismatch"
                | "D13SurfaceLength1228799"
                | "D13SurfaceLength1228801"
                | "D13TextBodyHash"
                | "D13TextHeaderReserved"
                | "D13TextHeaderVersion"
                | "D13TextLength127"
                | "D13TextLength4225"
                | "D13TextObjectMismatch"
                | "D14DuplicateAck"
                | "D14DuplicatePublish"
                | "D14FutureInput"
                | "D14OldRequest"
                | "D14WrongChannelGeneration"
                | "D16ExistingInodeAsNewCredit"
                | "D18CopiedOldCaptureRequest"
                | "D18UnsolicitedCapture"
                | "D25ActualSendBackpressure"
                | "D25EofWithPendingOffer"
                | "D25ShortRecord"
                | "D25StderrCapPlusOne"
                | "D25StdoutCapPlusOne"
                | "D27OldSurfaceGeneration"
                | "D28BackdatedCoreClock"
                | "D28RoundTripCannotRenew"
        )
    }
}

#[derive(Clone)]
pub(super) struct Trace {
    inner: Arc<TraceInner>,
}
struct TraceInner {
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    parent_case: Option<&'static str>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    started_at: Instant,
    state: Mutex<TraceState>,
    descriptor_ids: Arc<std::sync::atomic::AtomicU32>,
    changed: Condvar,
}
type RetainedNativeResource = (u64, Option<i32>, Option<(usize, usize)>);
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[derive(Clone)]
struct LazySnapshot {
    header: ProcessAssertionSnapshot,
    app: Arc<Vec<u8>>,
    composed: Arc<Vec<u8>>,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[derive(Clone)]
struct LazyObject {
    descriptor_id: u64,
    bytes: Arc<Vec<u8>>,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl LazyObject {
    fn materialize(&self) -> Result<ProcessAssertionObject, Status> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.bytes.len())
            .map_err(|_| Status::Exhausted)?;
        bytes.extend_from_slice(&self.bytes);
        Ok(ProcessAssertionObject {
            descriptor_id: self.descriptor_id,
            sha256: Sha256::digest(&bytes).into(),
            bytes,
        })
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
type CapturedObject = LazyObject;
#[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
type CapturedObject = ProcessAssertionObject;
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl LazySnapshot {
    fn materialize(&self) -> Result<ProcessAssertionSnapshot, Status> {
        let mut app = Vec::new();
        app.try_reserve_exact(self.app.len())
            .map_err(|_| Status::Exhausted)?;
        app.extend_from_slice(&self.app);
        let mut composed = Vec::new();
        composed
            .try_reserve_exact(self.composed.len())
            .map_err(|_| Status::Exhausted)?;
        composed.extend_from_slice(&self.composed);
        let app_sha256 = Sha256::digest(&app).into();
        let composed_sha256 = Sha256::digest(&composed).into();
        let mut header = self.header.clone();
        header.app_pixels = app;
        header.composed_pixels = composed;
        header.app_sha256 = app_sha256;
        header.composed_sha256 = composed_sha256;
        Ok(header)
    }
}
struct TraceState {
    scenario: Option<&'static ProcessAssertionScenario>,
    syscalls: Vec<ProcessAssertionSyscall>,
    descriptors: Vec<ProcessAssertionDescriptor>,
    objects: Vec<CapturedObject>,
    controls: Vec<ProcessAssertionControl>,
    control_reserved: u32,
    control_times: Vec<Instant>,
    control_syscalls: Vec<usize>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    processes: Vec<RecordedProcess>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    reference_calls: Vec<ProcessAssertionSyscall>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    references: Vec<Trace>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    scope_channel: Option<u64>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    bootstrap_send: Option<CapturedBootstrap>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    retired_bootstraps: Vec<RetiredBootstrapEvidence>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    fork_helpers: Vec<AssertionForkHelperEvidence>,
    points: Vec<ProcessAssertionCheckpoint>,
    blocked: Option<(ProcessAssertionPoint, u64)>,
    released: bool,
    cancelled: bool,
    owners: ProcessAssertionOwners,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    before: Option<LazySnapshot>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    candidate_kind: Option<u32>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    after: Option<LazySnapshot>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    snapshot_generation: u64,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    defer_retirement_snapshot: bool,
    executable: Option<ProcessAssertionExecutable>,
    admitted: Option<Instant>,
    deadline: Option<Instant>,
    native_wait: Option<ProcessWaitOutcome>,
    joined: bool,
    quarantined: bool,
    failed: bool,
    latest_status: Option<Status>,
    retained_raw: Vec<RetainedNativeResource>,
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    finished: Option<Arc<ProcessAssertionEvidence>>,
}
fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, Status> {
    mutex.lock().map_err(|_| Status::Internal)
}
impl Trace {
    pub(super) fn retirement_snapshot_deferred(&self) -> bool {
        #[cfg(feature = "host_editor_process_assertions_v0_dev")]
        {
            lock(&self.inner.state).map_or(true, |s| s.defer_retirement_snapshot)
        }
        #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
        {
            false
        }
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub(super) fn defer_late_publication_snapshot(&self) -> Result<(), Status> {
        let mut state = lock(&self.inner.state)?;
        if state
            .scenario
            .is_none_or(|s| s.id() != "D21PublicationAfterDeath")
            || state.after.is_some()
            || state.candidate_kind != Some(8)
        {
            return Err(Status::Stale);
        }
        state.defer_retirement_snapshot = true;
        Ok(())
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub(super) fn finish_late_publication_snapshot(&self) -> Result<(), Status> {
        let mut state = lock(&self.inner.state)?;
        if !state.defer_retirement_snapshot || state.native_wait.is_none() || !state.joined {
            return Err(Status::NotReady);
        }
        state.defer_retirement_snapshot = false;
        Ok(())
    }
    pub(super) fn descriptor_owner(&self, device: u64, inode: u64) -> Option<u32> {
        lock(&self.inner.state).ok().and_then(|s| {
            s.descriptors
                .iter()
                .rev()
                .find(|d| d.device == device && d.inode == inode && d.owner_process_id.is_some())
                .and_then(|d| d.owner_process_id)
        })
    }
    pub(super) fn new(
        descriptor_ids: Arc<std::sync::atomic::AtomicU32>,
        parent_case: Option<&'static str>,
    ) -> Self {
        #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
        let _ = parent_case;
        Self {
            inner: Arc::new(TraceInner {
                #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                parent_case,
                #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                started_at: Instant::now(),
                state: Mutex::new(TraceState {
                    scenario: None,
                    syscalls: Vec::new(),
                    descriptors: Vec::new(),
                    objects: Vec::new(),
                    controls: Vec::new(),
                    control_reserved: 0,
                    control_times: Vec::new(),
                    control_syscalls: Vec::new(),
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    processes: Vec::new(),
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    reference_calls: Vec::new(),
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    references: Vec::new(),
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    scope_channel: None,
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    bootstrap_send: None,
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    retired_bootstraps: Vec::new(),
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    fork_helpers: Vec::new(),
                    points: Vec::new(),
                    blocked: None,
                    released: false,
                    cancelled: false,
                    owners: ProcessAssertionOwners::default(),
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    before: None,
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    candidate_kind: None,
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    after: None,
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    snapshot_generation: 0,
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    defer_retirement_snapshot: false,
                    executable: None,
                    admitted: None,
                    deadline: None,
                    native_wait: None,
                    joined: false,
                    quarantined: false,
                    failed: false,
                    latest_status: None,
                    retained_raw: Vec::new(),
                    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                    finished: None,
                }),
                descriptor_ids,
                changed: Condvar::new(),
            }),
        }
    }
    pub(super) fn scenario(&self) -> Option<&'static ProcessAssertionScenario> {
        lock(&self.inner.state).ok().and_then(|s| s.scenario)
    }
    pub(super) fn is(&self, id: &str) -> bool {
        self.scenario().is_some_and(|s| s.id == id)
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub(super) fn bind(&self, scenario: &ProcessAssertionScenario) -> Result<(), Status> {
        let mut state = lock(&self.inner.state)?;
        if state.scenario.is_some() {
            return Err(Status::Stale);
        }
        state.scenario = Some(
            SCENARIOS
                .iter()
                .find(|s| s.id == scenario.id)
                .ok_or(Status::Invalid)?,
        );
        Ok(())
    }
    pub(super) fn admit(&self, at: Instant, deadline: Instant) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        if s.admitted.is_some() {
            return Err(Status::Stale);
        }
        s.admitted = Some(at);
        s.deadline = Some(deadline);
        Ok(())
    }
    pub(super) fn cancelled(&self) -> bool {
        lock(&self.inner.state).map_or(true, |s| s.cancelled || s.failed)
    }
    pub(super) fn call(
        &self,
        operation: ProcessAssertionOperation,
        result: i64,
        errno: Option<i32>,
        descriptor_id: Option<u64>,
    ) {
        self.syscall(ProcessAssertionSyscall {
            operation,
            origin: ProcessAssertionOrigin::Native,
            result,
            errno,
            descriptor_id,
            sender: None,
            msg_flags: 0,
            received_fds: 0,
            poll_revents: 0,
            ancillary: Vec::new(),
            ancillary_descriptor_ids: Vec::new(),
        });
    }
    pub(super) fn syscall(&self, row: ProcessAssertionSyscall) -> usize {
        if let Ok(mut s) = lock(&self.inner.state) {
            if s.scenario.is_none() {
                #[cfg(feature = "host_editor_process_assertions_v0_dev")]
                if matches!(
                    row.operation,
                    ProcessAssertionOperation::Fork
                        | ProcessAssertionOperation::Execveat
                        | ProcessAssertionOperation::PidfdOpen
                ) || row.operation == ProcessAssertionOperation::Waitpid && row.result > 0
                    || row.operation == ProcessAssertionOperation::Signal
                    || row.operation == ProcessAssertionOperation::Close
                        && row.descriptor_id.is_some_and(|id| {
                            s.bootstrap_send.as_ref().is_some_and(|b| {
                                b.descriptors.iter().any(|d| d.descriptor_id == id)
                            })
                        })
                {
                    if s.reference_calls.len() < 64 {
                        s.reference_calls.push(row);
                    } else {
                        s.failed = true;
                    }
                }
                return usize::MAX;
            }
            if s.syscalls.len() >= 131072 {
                s.failed = true;
                s.cancelled = true;
                return usize::MAX;
            }
            let index = s.syscalls.len();
            s.syscalls.push(row);
            self.inner.changed.notify_all();
            return index;
        }
        usize::MAX
    }
    pub(super) fn descriptor(&self, mut row: ProcessAssertionDescriptor) -> Result<u64, Status> {
        let mut s = lock(&self.inner.state)?;
        if row.descriptor_id == 0 {
            let previous = self
                .inner
                .descriptor_ids
                .fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |n| n.checked_add(1),
                )
                .map_err(|_| Status::Exhausted)?;
            row.descriptor_id = u64::from(previous) + 1;
        }
        let id = row.descriptor_id;
        if s.scenario.is_some() || {
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            {
                matches!(
                    row.role,
                    ProcessAssertionDescriptorRole::Pidfd
                        | ProcessAssertionDescriptorRole::Executable
                )
            }
            #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
            {
                false
            }
        } {
            if s.descriptors.len() >= 8192 {
                s.failed = true;
                return Err(Status::Exhausted);
            }
            s.descriptors.push(row);
        }
        Ok(id)
    }
    pub(super) fn disposition(
        &self,
        id: u64,
        disposition: ProcessAssertionDisposition,
        mapping: Option<ProcessAssertionMapping>,
    ) {
        if let Ok(mut s) = lock(&self.inner.state) {
            if let Some(row) = s
                .descriptors
                .iter()
                .rev()
                .find(|d| d.descriptor_id == id)
                .cloned()
            {
                let mut row = row;
                row.disposition = disposition;
                if let Some(m) = mapping {
                    row.mapping = m;
                }
                if s.descriptors.len() < 8192 {
                    s.descriptors.push(row);
                } else {
                    s.failed = true;
                }
            }
        }
    }
    pub(super) fn object(&self, id: u64, bytes: &[u8]) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        if s.scenario.is_none() {
            return Ok(());
        }
        if bytes.len() > desktop_editor_core::FRAME_BYTES + 1 || s.objects.len() >= 1024 {
            s.failed = true;
            return Err(Status::Exhausted);
        }
        #[cfg(feature = "host_editor_process_assertions_v0_dev")]
        s.objects.push(LazyObject {
            descriptor_id: id,
            bytes: Arc::new(bytes.to_vec()),
        });
        #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
        s.objects.push(ProcessAssertionObject {
            descriptor_id: id,
            bytes: bytes.to_vec(),
            sha256: Sha256::digest(bytes).into(),
        });
        Ok(())
    }
    pub(super) fn reserve_fd(&self, data: bool, length: u64, lifetime: bool) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        let o = &mut s.owners;
        if (data && o.data >= 12)
            || (!data && o.fixed >= 16)
            || o.combined >= 28
            || lifetime
                && (o.lifetime_objects >= 257
                    || o.lifetime_bytes
                        .checked_add(length)
                        .is_none_or(|n| n > 157831232))
        {
            return Err(Status::Exhausted);
        }
        if data {
            o.data += 1;
        } else {
            o.fixed += 1;
        }
        o.combined += 1;

        Ok(())
    }
    pub(super) fn release_fd(&self, data: bool) {
        if let Ok(mut s) = lock(&self.inner.state) {
            if data {
                s.owners.data = s.owners.data.saturating_sub(1);
            } else {
                s.owners.fixed = s.owners.fixed.saturating_sub(1);
            }
            s.owners.combined = s.owners.data + s.owners.fixed;
        }
    }
    pub(super) fn reserve_map(&self) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        let o = &mut s.owners;
        if o.maps >= 12 || o.data >= 12 || o.combined >= 28 {
            return Err(Status::Exhausted);
        }
        o.maps += 1;
        o.data += 1;
        o.combined += 1;
        Ok(())
    }
    pub(super) fn release_map(&self) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.owners.maps = s.owners.maps.saturating_sub(1);
            s.owners.data = s.owners.data.saturating_sub(1);
            s.owners.combined = s.owners.data + s.owners.fixed;
        }
    }
    pub(super) fn offer(&self) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        if s.owners.lifetime_offers >= 128 {
            return Err(Status::Exhausted);
        }
        s.owners.lifetime_offers += 1;
        Ok(())
    }
    pub(super) fn set_executable(&self, row: ProcessAssertionExecutable) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.executable = Some(row);
        }
    }
    pub(super) fn update_executable(&self, action: impl FnOnce(&mut ProcessAssertionExecutable)) {
        if let Ok(mut s) = lock(&self.inner.state) {
            if let Some(exe) = &mut s.executable {
                action(exe);
            }
        }
    }
    pub(super) fn terminal(&self, outcome: ProcessWaitOutcome) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.native_wait = Some(outcome);
            self.inner.changed.notify_all();
        }
    }
    pub(super) fn joined(&self) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.joined = true;
            s.owners.children = s.owners.children.saturating_sub(1);
            s.owners.supervisors = s.owners.supervisors.saturating_sub(1);
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            if let Some(row) = s.processes.first_mut() {
                row.supervisor_joined = true;
            }
            self.inner.changed.notify_all();
        }
    }
    pub(super) fn quarantine(&self) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.quarantined = true;
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            if let Some(row) = s.processes.first_mut() {
                row.quarantined = true;
            }
            s.cancelled = true;
            self.inner.changed.notify_all();
        }
    }
    pub(super) fn point(&self, point: ProcessAssertionPoint) -> Result<u64, Status> {
        let mut s = lock(&self.inner.state)?;
        if s.scenario.is_none() {
            return Ok(0);
        }
        let sequence = s.points.len() as u64 + 1;
        let now = Instant::now();
        s.points.push(ProcessAssertionCheckpoint {
            point,
            reached_at: now,
            sequence,
        });
        let blocking = s.scenario.is_some_and(|p| p.blocks(point));
        if !blocking {
            return Ok(sequence);
        }
        if s.blocked.is_some() {
            return Err(Status::NotReady);
        }
        s.blocked = Some((point, sequence));
        s.released = false;
        self.inner.changed.notify_all();
        while !s.released && !s.cancelled && !s.failed {
            let (next, _) = self
                .inner
                .changed
                .wait_timeout(s, Duration::from_millis(10))
                .map_err(|_| Status::Internal)?;
            s = next;
        }
        s.blocked = None;
        if s.cancelled || s.failed {
            return Err(Status::Disconnected);
        }
        Ok(sequence)
    }
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub(super) fn snapshot(
        &self,
        mut snapshot: ProcessAssertionSnapshot,
        app: Arc<Vec<u8>>,
        composed: Arc<Vec<u8>>,
        before: bool,
    ) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        snapshot.syscall_count = s.syscalls.len() as u64;
        snapshot.control_count = s.controls.len() as u64;
        snapshot.descriptor_count = s.descriptors.len() as u64;
        snapshot.owners.data = s.owners.data;
        snapshot.owners.fixed = s.owners.fixed;
        snapshot.owners.combined = s.owners.combined;
        snapshot.owners.maps = s.owners.maps;
        snapshot.owners.lifetime_objects = s.owners.lifetime_objects;
        snapshot.owners.lifetime_bytes = s.owners.lifetime_bytes;
        snapshot.owners.lifetime_offers = s.owners.lifetime_offers;
        snapshot.admitted_at = s.admitted;
        snapshot.child_deadline = s.deadline;
        if before {
            if s.after.is_some() || s.candidate_kind.is_some() {
                return Ok(());
            }
            s.snapshot_generation = s
                .snapshot_generation
                .checked_add(1)
                .ok_or(Status::Exhausted)?;
            s.before = Some(LazySnapshot {
                header: snapshot,
                app,
                composed,
            });
        } else if s.after.is_none() {
            s.snapshot_generation = s
                .snapshot_generation
                .checked_add(1)
                .ok_or(Status::Exhausted)?;
            s.after = Some(LazySnapshot {
                header: snapshot,
                app,
                composed,
            });
        }
        Ok(())
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl Trace {
    pub(super) fn needs_snapshot(&self, before: bool) -> bool {
        lock(&self.inner.state).is_ok_and(|s| {
            s.scenario.is_some() && s.after.is_none() && (!before || s.candidate_kind.is_none())
        })
    }
    pub(super) fn candidate_kind(&self) -> Option<u32> {
        lock(&self.inner.state).ok().and_then(|s| s.candidate_kind)
    }
    pub(super) fn release_candidate(&self) -> Option<u32> {
        lock(&self.inner.state)
            .ok()
            .and_then(|mut s| s.candidate_kind.take())
    }
    pub(super) fn hold_candidate(&self, kind: u32) -> Result<(), Status> {
        lock(&self.inner.state)?.candidate_kind = Some(kind);
        Ok(())
    }
}
impl ProcessAssertionScenario {
    fn blocks(&self, point: ProcessAssertionPoint) -> bool {
        use ProcessAssertionPoint::*;
        match self.id {
            "D02PostHeldPathReplacement" | "D02PostHeldInodeMutation" => {
                point == HeldVerifiedBeforeExec
            }
            "D18CaptureAfter1000Ms"
            | "D18RoundTripCannotRenewCapture"
            | "D28IntentRequestCannotRenew" => point == CaptureBeforeAdopt,
            "D28SpawnPauseCannotRenew" => point == ForkOwnedBeforeExecRelease,
            "D28BootstrapPauseCannotRenew" => point == BootstrapBeforeSend,
            "D28RoundTripCannotRenew" | "D28BackdatedCoreClock" => point == InputReceivedBeforeAck,
            "D24NoRegistryLockAcrossSignalWait" => {
                matches!(point, SupervisorBeforeSignal | SupervisorBeforeWait)
            }
            "D29DropIsNotReap" => point == SupervisorBeforeSignal,
            "D19OlderReceiptThenFreshAuthorizedSave" => point == PairValidatedBeforeAdopt,
            _ => false,
        }
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub struct ProcessAssertionRun {
    pub(super) scope: RunScope,
    pub(super) trace: Trace,
    authority: Arc<NativeAuthority>,
    document: u64,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub struct ProcessAssertionFinishFailure {
    status: Status,
    run: ProcessAssertionRun,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl ProcessAssertionFinishFailure {
    pub fn into_parts(self) -> (Status, ProcessAssertionRun) {
        (self.status, self.run)
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub struct ProcessAssertionEvidence {
    pub(super) active_channel_generation: u64,
    pub(super) scenario: &'static str,
    pub(super) before: ProcessAssertionSnapshot,
    pub(super) after: ProcessAssertionSnapshot,
    pub(super) syscalls: Vec<ProcessAssertionSyscall>,
    pub(super) descriptors: Vec<ProcessAssertionDescriptor>,
    pub(super) objects: Vec<ProcessAssertionObject>,
    pub(super) controls: Vec<ProcessAssertionControl>,
    pub(super) control_times: Vec<Instant>,
    pub(super) control_syscalls: Vec<usize>,
    pub(super) processes: Vec<RecordedProcess>,
    pub(super) referenced_processes: Vec<ReferencedProcessEvidence>,
    pub(super) retired_bootstraps: Vec<RetiredBootstrapEvidence>,
    pub(super) fork_helpers: Vec<AssertionForkHelperEvidence>,
    pub(super) points: Vec<ProcessAssertionCheckpoint>,
    pub(super) wait: Option<ProcessWaitOutcome>,
    pub(super) joined: bool,
    pub(super) quarantined: bool,
    pub(super) executable: Option<ProcessAssertionExecutable>,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl ProcessAssertionEvidence {
    pub fn scenario_id(&self) -> &'static str {
        self.scenario
    }
    pub fn active_channel_generation(&self) -> u64 {
        self.active_channel_generation
    }
    pub fn before(&self) -> &ProcessAssertionSnapshot {
        &self.before
    }
    pub fn after(&self) -> &ProcessAssertionSnapshot {
        &self.after
    }
    pub fn syscalls(&self) -> &[ProcessAssertionSyscall] {
        &self.syscalls
    }
    pub fn descriptors(&self) -> &[ProcessAssertionDescriptor] {
        &self.descriptors
    }
    pub fn objects(&self) -> &[ProcessAssertionObject] {
        &self.objects
    }
    pub fn controls(&self) -> &[ProcessAssertionControl] {
        &self.controls
    }
    pub fn checkpoints(&self) -> &[ProcessAssertionCheckpoint] {
        &self.points
    }
    pub fn native_wait_outcome(&self) -> Option<ProcessWaitOutcome> {
        self.wait
    }
    pub fn supervisor_joined(&self) -> bool {
        self.joined
    }
    pub fn quarantined(&self) -> bool {
        self.quarantined
    }
    pub fn executable(&self) -> Option<&ProcessAssertionExecutable> {
        self.executable.as_ref()
    }
    pub fn retired_bootstrap_sources(
        &self,
    ) -> impl Iterator<Item = (&[u8; 88], u32, u64, u64)> + '_ {
        self.retired_bootstraps.iter().filter_map(|h| {
            let p = h.processes.first()?;
            Some((&h.bytes, p.child_pid?, p.birth_ticks?, h.channel_generation))
        })
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl ProcessAssertionRun {
    pub fn wait_checkpoint(
        &self,
        point: ProcessAssertionPoint,
        timeout_ms: u32,
    ) -> Result<ProcessAssertionCheckpoint, Status> {
        if !(1..=5000).contains(&timeout_ms) {
            return Err(Status::Invalid);
        }
        let end = Instant::now() + Duration::from_millis(timeout_ms as u64);
        let mut s = lock(&self.trace.inner.state)?;
        loop {
            if let Some((p, sequence)) = s.blocked {
                if p == point && !s.released {
                    return s
                        .points
                        .iter()
                        .find(|c| c.sequence == sequence)
                        .cloned()
                        .ok_or(Status::Internal);
                }
            }
            if s.cancelled {
                return Err(Status::Stale);
            }
            let Some(left) = end.checked_duration_since(Instant::now()) else {
                return Err(Status::NotReady);
            };
            let (next, _) = self
                .trace
                .inner
                .changed
                .wait_timeout(s, left)
                .map_err(|_| Status::Internal)?;
            s = next;
        }
    }
    pub fn release(&mut self, point: ProcessAssertionPoint) -> Result<(), Status> {
        let mut s = lock(&self.trace.inner.state)?;
        if s.released || s.blocked.is_none_or(|(p, _)| p != point) {
            return Err(Status::Invalid);
        }
        s.released = true;
        self.trace.inner.changed.notify_all();
        Ok(())
    }
    pub fn finish_recording(
        self,
    ) -> Result<ProcessAssertionEvidence, ProcessAssertionFinishFailure> {
        let result = (|| {
            let (references, before, after, generation, objects) = {
                let s = lock(&self.trace.inner.state)?;
                if let Some(evidence) = &s.finished {
                    return Ok(evidence.clone());
                }
                if s.failed
                    || s.quarantined
                    || s.owners.combined != 0
                    || s.owners.maps != 0
                    || s.owners.children != 0
                    || s.owners.supervisors != 0
                    || s.native_wait.is_some() && !s.joined
                {
                    return Err(Status::NotReady);
                }
                (
                    s.references.clone(),
                    s.before.clone().ok_or(Status::NotReady)?,
                    s.after.clone().ok_or(Status::NotReady)?,
                    s.snapshot_generation,
                    s.objects.clone(),
                )
            };
            let referenced_processes = references
                .iter()
                .map(Trace::referenced_evidence)
                .collect::<Result<Vec<_>, _>>()?;
            // Immutable Core pixels are pinned at the original decision
            // boundary. Copying and full hashing are deferred, not sampled,
            // and happen with no Core, process or Trace lock held.
            let before = before.materialize()?;
            let after = after.materialize()?;
            // Every original byte observation is pinned in append order.
            // Only its diagnostic hash/copy is deferred beyond child cleanup;
            // enforcing inode, seal, body and Surface hashes remain immediate.
            let mut materialized_objects = Vec::new();
            materialized_objects
                .try_reserve_exact(objects.len())
                .map_err(|_| Status::Exhausted)?;
            for object in &objects {
                materialized_objects.push(object.materialize()?);
            }
            let mut s = lock(&self.trace.inner.state)?;
            if let Some(evidence) = &s.finished {
                return Ok(evidence.clone());
            }
            if s.failed
                || s.quarantined
                || s.owners.combined != 0
                || s.owners.maps != 0
                || s.owners.children != 0
                || s.owners.supervisors != 0
                || s.native_wait.is_some() && !s.joined
                || s.snapshot_generation != generation
                || s.objects.len() != objects.len()
                || s.objects.iter().zip(&objects).any(|(stored, pinned)| {
                    stored.descriptor_id != pinned.descriptor_id
                        || !Arc::ptr_eq(&stored.bytes, &pinned.bytes)
                })
            {
                return Err(Status::NotReady);
            }
            let evidence = Arc::new(ProcessAssertionEvidence {
                active_channel_generation: s.scope_channel.unwrap_or(0),
                scenario: s.scenario.ok_or(Status::NotReady)?.id,
                before,
                after,
                syscalls: std::mem::take(&mut s.syscalls),
                descriptors: std::mem::take(&mut s.descriptors),
                objects: materialized_objects,
                controls: std::mem::take(&mut s.controls),
                control_times: std::mem::take(&mut s.control_times),
                control_syscalls: std::mem::take(&mut s.control_syscalls),
                processes: std::mem::take(&mut s.processes),
                referenced_processes,
                retired_bootstraps: s.retired_bootstraps.clone(),
                fork_helpers: std::mem::take(&mut s.fork_helpers),
                points: std::mem::take(&mut s.points),
                wait: s.native_wait,
                joined: s.joined,
                quarantined: s.quarantined,
                executable: s.executable.take(),
            });
            s.objects.clear();
            s.finished = Some(evidence.clone());
            Ok(evidence)
        })();
        let result = result.and_then(|evidence| {
            // Persistence may block on the corpus budget or filesystem. The
            // immutable evidence remains owned by this Run on every error;
            // no process, Trace or Core lock is held across filesystem I/O.
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            super::recording::persist(&evidence, &self.scope)?;
            lock(&self.trace.inner.state)?.finished = None;
            Arc::try_unwrap(evidence).map_err(|evidence| {
                if let Ok(mut s) = lock(&self.trace.inner.state) {
                    s.finished = Some(evidence);
                }
                Status::Internal
            })
        });
        result.map_err(|status| ProcessAssertionFinishFailure { status, run: self })
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl Drop for ProcessAssertionRun {
    fn drop(&mut self) {
        if let Ok(mut s) = lock(&self.trace.inner.state) {
            s.cancelled = true;
            self.trace.inner.changed.notify_all();
        }
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl super::super::FixtureController {
    pub fn arm_process_assertion(
        &self,
        enrollment: &ProcessEditorEnrollment,
        scenario: &ProcessAssertionScenario,
    ) -> Result<ProcessAssertionRun, Status> {
        if !Arc::ptr_eq(
            &self.process_host().process_authority()?,
            &enrollment.editor.authority,
        ) {
            return Err(Status::Denied);
        }
        enrollment.trace.bind(scenario)?;
        if scenario.id() == "D23OldBootstrapDenied" {
            let history = enrollment
                .roster
                .lock()
                .map_err(|_| Status::Internal)?
                .retired_bootstraps
                .iter()
                .cloned()
                .collect();
            lock(&enrollment.trace.inner.state)?.retired_bootstraps = history;
        }
        if scenario.id() == "D14ChannelCounterMax" {
            *enrollment
                .channel_admission
                .lock()
                .map_err(|_| Status::Internal)? = Some(u64::MAX);
        }
        Ok(ProcessAssertionRun {
            scope: RunScope {
                parent_case: enrollment.trace.inner.parent_case.ok_or(Status::Invalid)?,
                scenario_id: scenario.id(),
                parent_pid: unsafe { libc::getpid() } as u32,
                started_at: enrollment.trace.inner.started_at,
                run_ordinal: std::sync::atomic::AtomicU64::new(0),
            },
            trace: enrollment.trace.clone(),
            authority: enrollment.editor.authority.clone(),
            document: enrollment.seed.view.document_id,
        })
    }
    pub fn arm_process_pair_assertion(
        &self,
        enrollment: &ProcessEditorEnrollment,
        sibling: &OwnedEditorChild,
        scenario: &ProcessAssertionScenario,
    ) -> Result<ProcessAssertionRun, Status> {
        let sibling = sibling.inner.as_ref().ok_or(Status::Stale)?;
        if !Arc::ptr_eq(&enrollment.editor.authority, &sibling.record.authority)
            || enrollment.seed.view.document_id == sibling.enrollment.seed.view.document_id
        {
            return Err(Status::Denied);
        }
        if !sibling.ready || sibling.accepted.is_none() {
            return Err(Status::NotReady);
        }
        let run = self.arm_process_assertion(enrollment, scenario)?;
        enrollment.trace.reference(&sibling.record.trace)?;
        if matches!(
            scenario.id(),
            "D12ForeignChildText" | "D12ForeignChildSurface" | "D12EqualBytesForeignInode"
        ) {
            super::fixtures::bind_pair(enrollment, sibling)?;
        }
        if scenario.id() == "D14ForeignDocumentBinding" {
            super::fixtures::bind_document(enrollment, sibling)?;
        }
        Ok(run)
    }
    pub fn join_process_assertion_quarantine(
        &self,
        run: &mut ProcessAssertionRun,
    ) -> Result<OwnedEditorChildExitProof, ProcessStepFailure> {
        if !Arc::ptr_eq(&self.process_host().process_authority()?, &run.authority) {
            return Err(Status::Denied.into());
        }
        let roster = self.process_host().process_roster()?;
        let child = {
            let mut r = lock(&roster)?;
            let index = r
                .parked
                .iter()
                .position(|c| {
                    c.inner
                        .as_ref()
                        .is_some_and(|i| i.enrollment.seed.view.document_id == run.document)
                })
                .ok_or(Status::NotReady)?;
            r.parked.swap_remove(index)
        };
        match self.process_host().join_process_editor(child) {
            Ok(proof) => Ok(proof),
            Err(failure) => {
                let (status, child) = failure.into_parts();
                let mut r = lock(&roster)?;
                r.parked.push(child);
                Err(status.into())
            }
        }
    }

    /// Retain descriptive provenance for an unrelated actual child in this
    /// assertion case. Its own supervisor must finish before recording can.
    pub fn reference_process_assertion(
        &self,
        run: &mut ProcessAssertionRun,
        sibling: &OwnedEditorChild,
    ) -> Result<(), Status> {
        let sibling = sibling.inner.as_ref().ok_or(Status::Stale)?;
        if !Arc::ptr_eq(&self.process_host().process_authority()?, &run.authority)
            || !Arc::ptr_eq(&run.authority, &sibling.record.authority)
            || run.document == sibling.enrollment.seed.view.document_id
            || sibling.record.trace.inner.parent_case != Some(run.scope.parent_case)
        {
            return Err(Status::Denied);
        }
        run.trace.reference(&sibling.record.trace)
    }
}
impl Trace {
    pub(super) fn child_point(&self, point: ProcessAssertionPoint) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        if s.blocked.is_some() {
            return Err(Status::NotReady);
        }
        let scenario = s.scenario.ok_or(Status::Invalid)?;
        if !scenario.assertion_child()
            || !scenario.blocks(point)
            || s.points.iter().any(|p| p.point == point)
        {
            return Err(Status::Invalid);
        }
        let sequence = s.points.len() as u64 + 1;
        s.points.push(ProcessAssertionCheckpoint {
            point,
            reached_at: Instant::now(),
            sequence,
        });
        s.blocked = Some((point, sequence));
        s.released = false;
        self.inner.changed.notify_all();
        Ok(())
    }
    pub(super) fn child_released(&self) -> bool {
        if let Ok(mut s) = lock(&self.inner.state) {
            if s.blocked.is_some() && s.released {
                s.blocked = None;
                return true;
            }
        }
        false
    }
}

impl Trace {
    pub(super) fn retain_uncertain(
        &self,
        id: u64,
        fd: Option<i32>,
        mapping: Option<(usize, usize)>,
    ) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.quarantined = true;
            s.cancelled = true;
            s.retained_raw.push((id, fd, mapping));
            self.inner.changed.notify_all();
        }
        std::mem::forget(self.clone());
    }
}

impl Trace {
    pub(super) fn commit_lifetime(&self, length: u64) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        s.owners.lifetime_objects = s
            .owners
            .lifetime_objects
            .checked_add(1)
            .ok_or(Status::Exhausted)?;
        s.owners.lifetime_bytes = s
            .owners
            .lifetime_bytes
            .checked_add(length)
            .ok_or(Status::Exhausted)?;
        Ok(())
    }
    pub(super) fn grow_lifetime(&self, length: u64) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        s.owners.lifetime_bytes = s
            .owners
            .lifetime_bytes
            .checked_add(length)
            .ok_or(Status::Exhausted)?;
        Ok(())
    }
}

impl Trace {
    pub(super) fn fail_recording(&self) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.failed = true;
            s.cancelled = true;
            self.inner.changed.notify_all();
        }
    }
}
impl Trace {
    #[cfg(feature = "host_editor_process_assertions_v0_dev")]
    pub(super) fn owners(&self) -> ProcessAssertionOwners {
        lock(&self.inner.state)
            .map(|s| s.owners.clone())
            .unwrap_or_default()
    }
    pub(super) fn forked(&self) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.owners.children = 1;
        }
    }
    pub(super) fn started(&self) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.owners.supervisors = 1;
        }
    }
    pub(super) fn quarantined(&self) -> bool {
        lock(&self.inner.state).map_or(true, |s| s.quarantined)
    }
}

impl Trace {
    pub(super) fn note_status(&self, status: Status) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.latest_status = Some(status);
        }
    }
    pub(super) fn latest_status(&self) -> Option<Status> {
        lock(&self.inner.state).ok().and_then(|s| s.latest_status)
    }
    pub(super) fn has_after(&self) -> bool {
        #[cfg(feature = "host_editor_process_assertions_v0_dev")]
        {
            lock(&self.inner.state).map_or(true, |s| s.after.is_some())
        }
        #[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
        {
            false
        }
    }
}

impl Trace {
    pub(super) fn inject_once(&self, operation: ProcessAssertionOperation, errno: i32) -> bool {
        let Ok(mut state) = lock(&self.inner.state) else {
            return false;
        };
        if state.syscalls.iter().any(|row| {
            row.operation == operation
                && row.origin == ProcessAssertionOrigin::InjectedBeforeSyscall
        }) {
            return false;
        }
        state.syscalls.push(ProcessAssertionSyscall {
            operation,
            origin: ProcessAssertionOrigin::InjectedBeforeSyscall,
            result: -1,
            errno: Some(errno),
            sender: None,
            msg_flags: 0,
            received_fds: 0,
            descriptor_id: None,
            poll_revents: 0,
            ancillary: Vec::new(),
            ancillary_descriptor_ids: Vec::new(),
        });
        true
    }
    pub(super) fn inject(
        &self,
        operation: ProcessAssertionOperation,
        origin: ProcessAssertionOrigin,
        errno: i32,
    ) {
        self.syscall(ProcessAssertionSyscall {
            operation,
            origin,
            result: -1,
            errno: Some(errno),
            sender: None,
            msg_flags: 0,
            received_fds: 0,
            descriptor_id: None,
            poll_revents: 0,
            ancillary: Vec::new(),
            ancillary_descriptor_ids: Vec::new(),
        });
    }
}

pub(super) struct ControlReservation {
    trace: Trace,
    active: bool,
    payload: Vec<u8>,
}
impl Trace {
    pub(super) fn reserve_control(&self) -> Result<ControlReservation, Status> {
        let mut state = lock(&self.inner.state)?;
        if state.scenario.is_none() {
            return Ok(ControlReservation {
                trace: self.clone(),
                active: false,
                payload: Vec::new(),
            });
        }
        if state.controls.len() + state.control_reserved as usize >= 32768 {
            return Err(Status::Exhausted);
        }
        let needed = state.control_reserved as usize + 1;
        state
            .controls
            .try_reserve(needed)
            .map_err(|_| Status::Exhausted)?;
        state
            .control_times
            .try_reserve(needed)
            .map_err(|_| Status::Exhausted)?;
        state
            .control_syscalls
            .try_reserve(needed)
            .map_err(|_| Status::Exhausted)?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(89)
            .map_err(|_| Status::Exhausted)?;
        state.control_reserved += 1;
        Ok(ControlReservation {
            trace: self.clone(),
            active: true,
            payload,
        })
    }
}
impl ControlReservation {
    pub(super) fn commit(
        mut self,
        direction: ProcessAssertionDirection,
        bytes: &[u8],
        sender: Option<(u32, u32, u32)>,
        msg_flags: u32,
        received_fds: u32,
        syscall_index: usize,
    ) -> Result<(), Status> {
        if !self.active {
            return Ok(());
        }
        if bytes.len() > 89 {
            return Err(Status::Invalid);
        }
        self.payload.extend_from_slice(bytes);
        let mut state = lock(&self.trace.inner.state)?;
        let sequence = state.controls.len() as u64 + 1;
        let payload = std::mem::take(&mut self.payload);
        state.controls.push(ProcessAssertionControl {
            direction,
            bytes: payload,
            sender,
            msg_flags,
            received_fds,
            sequence,
        });
        state.control_times.push(Instant::now());
        state.control_syscalls.push(syscall_index);
        state.control_reserved -= 1;
        self.active = false;
        Ok(())
    }
}
impl Drop for ControlReservation {
    fn drop(&mut self) {
        if self.active {
            if let Ok(mut state) = lock(&self.trace.inner.state) {
                state.control_reserved = state.control_reserved.saturating_sub(1);
            }
        }
    }
}

impl ProcessAssertionScenario {
    pub(super) fn is_positive(&self) -> bool {
        SCENARIOS[223..].iter().any(|s| s.id == self.id)
    }
}

#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) struct RunScope {
    pub(super) parent_case: &'static str,
    pub(super) scenario_id: &'static str,
    pub(super) parent_pid: u32,
    pub(super) started_at: Instant,
    pub(super) run_ordinal: std::sync::atomic::AtomicU64,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl super::super::FixtureController {
    pub fn bind_process_recording_case(&self, case: &'static str) -> Result<(), Status> {
        if case.is_empty()
            || case.len() > 128
            || !case
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
        {
            return Err(Status::Invalid);
        }
        let roster = self.process_host().process_roster()?;
        let mut roster = lock(&roster)?;
        if roster.prepared || roster.parent_case.is_some() {
            return Err(Status::Stale);
        }
        roster.parent_case = Some(case);
        Ok(())
    }
}

#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[derive(Clone)]
pub(super) struct RecordedProcess {
    pub(super) parent_pid: u32,
    pub(super) child_pid: Option<u32>,
    pub(super) birth_ticks: Option<u64>,
    pub(super) pidfd_ledger_id: Option<u64>,
    pub(super) supervisor_native_tid: u32,
    pub(super) supervisor_rust_id: String,
    pub(super) wait_raw_status: Option<i32>,
    pub(super) wait_outcome: Option<ProcessWaitOutcome>,
    pub(super) supervisor_joined: bool,
    pub(super) quarantined: bool,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) struct ReferencedProcessEvidence {
    pub(super) parent_case: &'static str,
    pub(super) channel_generation: u64,
    pub(super) scenario_id: Option<&'static str>,
    pub(super) processes: Vec<RecordedProcess>,
    pub(super) syscalls: Vec<ProcessAssertionSyscall>,
    pub(super) descriptors: Vec<ProcessAssertionDescriptor>,
    pub(super) executable: Option<ProcessAssertionExecutable>,
    pub(super) owners_after_cleanup: ProcessAssertionOwners,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
pub(super) struct AssertionForkHelperEvidence {
    pub(super) parent_case: &'static str,
    pub(super) scenario_id: &'static str,
    pub(super) channel_generation: u64,
    pub(super) process: RecordedProcess,
    pub(super) syscall_indices: Vec<usize>,
    pub(super) received_syscall_index: usize,
    pub(super) descriptors: Vec<ProcessAssertionDescriptor>,
    pub(super) creation_peer_credentials: Option<(u32, u32, u32)>,
    pub(super) received_credentials: (u32, u32, u32),
    pub(super) endpoint_aliases_after_cleanup: u32,
    pub(super) helper_slots_after_cleanup: u32,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl Trace {
    pub(super) fn helper_started(&self) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        if s.owners.supervisors >= 2 {
            return Err(Status::Exhausted);
        }
        s.owners.supervisors += 1;
        Ok(())
    }
    pub(super) fn reserve_helper_child(&self) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        if s.owners.children >= 2 {
            return Err(Status::Exhausted);
        }
        s.owners.children += 1;
        Ok(())
    }
    pub(super) fn helper_waited(&self) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.owners.children = s.owners.children.saturating_sub(1);
        }
    }
    pub(super) fn helper_joined(&self) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.owners.supervisors = s.owners.supervisors.saturating_sub(1);
        }
    }
    pub(super) fn native_close_index(&self, id: u64) -> Option<usize> {
        lock(&self.inner.state)
            .ok()?
            .syscalls
            .iter()
            .enumerate()
            .rev()
            .find(|(_, r)| {
                r.operation == ProcessAssertionOperation::Close
                    && r.descriptor_id == Some(id)
                    && r.result == 0
            })
            .map(|(i, _)| i)
    }
    pub(super) fn save_helper(&self, helper: AssertionForkHelperEvidence) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        if !s.fork_helpers.is_empty() {
            return Err(Status::Exhausted);
        }
        s.fork_helpers.push(helper);
        Ok(())
    }
    pub(super) fn parent_case(&self) -> Option<&'static str> {
        self.inner.parent_case
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
#[derive(Clone)]
pub(super) struct RetiredBootstrapEvidence {
    pub(super) parent_case: &'static str,
    pub(super) scenario_id: Option<&'static str>,
    pub(super) channel_generation: u64,
    pub(super) bytes: [u8; 88],
    pub(super) send: ProcessAssertionSyscall,
    pub(super) processes: Vec<RecordedProcess>,
    pub(super) proof_syscalls: Vec<ProcessAssertionSyscall>,
    pub(super) descriptors: Vec<ProcessAssertionDescriptor>,
    pub(super) executable: Option<ProcessAssertionExecutable>,
    pub(super) owners_after_cleanup: ProcessAssertionOwners,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
struct CapturedBootstrap {
    bytes: [u8; 88],
    send: ProcessAssertionSyscall,
    descriptors: Vec<ProcessAssertionDescriptor>,
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl Trace {
    pub(super) fn capture_bootstrap(
        &self,
        bytes: &[u8],
        send: ProcessAssertionSyscall,
        descriptors: Vec<ProcessAssertionDescriptor>,
    ) -> Result<(), Status> {
        if bytes.len() != 88
            || u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Status::Invalid)?) != 1
            || send.result != 88
            || send.ancillary_descriptor_ids.len() != 3
        {
            return Ok(());
        }
        let mut state = lock(&self.inner.state)?;
        let channel = u64::from_le_bytes(bytes[28..36].try_into().map_err(|_| Status::Invalid)?);
        if state.scope_channel != Some(channel) || state.bootstrap_send.is_some() {
            return Ok(());
        }
        state.bootstrap_send = Some(CapturedBootstrap {
            bytes: bytes.try_into().map_err(|_| Status::Invalid)?,
            send,
            descriptors,
        });
        Ok(())
    }
    pub(super) fn retired_bootstrap(&self) -> Result<RetiredBootstrapEvidence, Status> {
        let state = lock(&self.inner.state)?;
        if state.failed
            || state.quarantined
            || !state.joined
            || state.native_wait.is_none()
            || state.owners.combined != 0
            || state.owners.maps != 0
            || state.owners.children != 0
            || state.owners.supervisors != 0
        {
            return Err(Status::NotReady);
        }
        let source = state.bootstrap_send.as_ref().ok_or(Status::NotReady)?;
        let process = state.processes.first().ok_or(Status::NotReady)?;
        if process.child_pid.is_none()
            || process.birth_ticks.is_none()
            || process.wait_raw_status.is_none()
            || !process.supervisor_joined
            || process.quarantined
        {
            return Err(Status::NotReady);
        }
        let calls = if state.scenario.is_some() {
            &state.syscalls
        } else {
            &state.reference_calls
        };
        let mut descriptors = state
            .descriptors
            .iter()
            .filter(|d| {
                matches!(
                    d.role,
                    ProcessAssertionDescriptorRole::Executable
                        | ProcessAssertionDescriptorRole::Pidfd
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        descriptors.extend(source.descriptors.clone());
        Ok(RetiredBootstrapEvidence {
            parent_case: self.inner.parent_case.ok_or(Status::Invalid)?,
            scenario_id: state.scenario.map(|s| s.id()),
            channel_generation: state.scope_channel.ok_or(Status::Invalid)?,
            bytes: source.bytes,
            send: source.send.clone(),
            processes: state.processes.clone(),
            proof_syscalls: calls
                .iter()
                .filter(|c| {
                    matches!(
                        c.operation,
                        ProcessAssertionOperation::Fork
                            | ProcessAssertionOperation::Execveat
                            | ProcessAssertionOperation::PidfdOpen
                            | ProcessAssertionOperation::Signal
                    ) || c.operation == ProcessAssertionOperation::Waitpid && c.result > 0
                        || c.operation == ProcessAssertionOperation::Close
                            && c.descriptor_id
                                .is_some_and(|id| descriptors.iter().any(|d| d.descriptor_id == id))
                })
                .cloned()
                .collect(),
            descriptors,
            executable: state.executable.clone(),
            owners_after_cleanup: state.owners.clone(),
        })
    }
    pub(super) fn old_bootstrap_bytes(&self) -> Option<[u8; 88]> {
        lock(&self.inner.state)
            .ok()?
            .retired_bootstraps
            .last()
            .map(|h| h.bytes)
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl Trace {
    pub(super) fn record_channel(&self, channel: u64) -> Result<(), Status> {
        let mut state = lock(&self.inner.state)?;
        if state.scope_channel.is_some() {
            return Err(Status::Stale);
        }
        state.scope_channel = Some(channel);
        Ok(())
    }
    fn reference(&self, other: &Trace) -> Result<(), Status> {
        if Arc::ptr_eq(&self.inner, &other.inner) {
            return Err(Status::Denied);
        }
        let mut state = lock(&self.inner.state)?;
        if state.finished.is_some() {
            return Err(Status::Stale);
        }
        if state
            .references
            .iter()
            .any(|r| Arc::ptr_eq(&r.inner, &other.inner))
        {
            return Err(Status::Stale);
        }
        if state.references.len() >= 7 {
            return Err(Status::Exhausted);
        }
        state.references.push(other.clone());
        Ok(())
    }
    fn referenced_evidence(&self) -> Result<ReferencedProcessEvidence, Status> {
        let state = lock(&self.inner.state)?;
        if state.quarantined
            || state.failed
            || !state.joined
            || state.native_wait.is_none()
            || state.owners.children != 0
            || state.owners.supervisors != 0
            || state.owners.combined != 0
            || state.owners.maps != 0
        {
            return Err(Status::NotReady);
        }
        if state.processes.is_empty()
            || state.processes.iter().any(|p| {
                !p.supervisor_joined
                    || p.quarantined
                    || p.wait_raw_status.is_none()
                    || p.child_pid.is_none()
                    || p.birth_ticks.is_none()
            })
        {
            return Err(Status::NotReady);
        }
        Ok(ReferencedProcessEvidence {
            parent_case: self.inner.parent_case.ok_or(Status::Invalid)?,
            channel_generation: state.scope_channel.ok_or(Status::Invalid)?,
            scenario_id: state.scenario.map(|s| s.id()),
            processes: state.processes.clone(),
            syscalls: state
                .reference_calls
                .iter()
                .filter(|c| {
                    matches!(
                        c.operation,
                        ProcessAssertionOperation::Fork
                            | ProcessAssertionOperation::Execveat
                            | ProcessAssertionOperation::PidfdOpen
                    ) || c.operation == ProcessAssertionOperation::Waitpid && c.result > 0
                })
                .cloned()
                .collect(),
            descriptors: state
                .descriptors
                .iter()
                .filter(|d| {
                    matches!(
                        d.role,
                        ProcessAssertionDescriptorRole::Pidfd
                            | ProcessAssertionDescriptorRole::Executable
                    )
                })
                .cloned()
                .collect(),
            executable: state.executable.clone(),
            owners_after_cleanup: state.owners.clone(),
        })
    }
}
#[cfg(feature = "host_editor_process_assertions_v0_dev")]
impl Trace {
    pub(super) fn process_started(&self) {
        if let Ok(mut s) = lock(&self.inner.state) {
            s.processes.push(RecordedProcess {
                parent_pid: unsafe { libc::getpid() } as u32,
                child_pid: None,
                birth_ticks: None,
                pidfd_ledger_id: None,
                supervisor_native_tid: unsafe { libc::syscall(libc::SYS_gettid) } as u32,
                supervisor_rust_id: format!("{:?}", std::thread::current().id()),
                wait_raw_status: None,
                wait_outcome: None,
                supervisor_joined: false,
                quarantined: false,
            });
        }
    }
    pub(super) fn process_forked(&self, pid: u32) {
        self.forked();
        if let Ok(mut s) = lock(&self.inner.state) {
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            if let Some(row) = s.processes.first_mut() {
                row.child_pid = Some(pid);
            }
        }
    }
    pub(super) fn process_birth(&self, birth: u64) {
        if let Ok(mut s) = lock(&self.inner.state) {
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            if let Some(row) = s.processes.first_mut() {
                row.birth_ticks = Some(birth);
            }
        }
    }
    pub(super) fn process_pidfd(&self, id: u64) {
        if let Ok(mut s) = lock(&self.inner.state) {
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            if let Some(row) = s.processes.first_mut() {
                row.pidfd_ledger_id = Some(id);
            }
        }
    }
    pub(super) fn process_wait(&self, raw: i32, outcome: ProcessWaitOutcome) {
        if let Ok(mut s) = lock(&self.inner.state) {
            #[cfg(feature = "host_editor_process_assertions_v0_dev")]
            if let Some(row) = s.processes.first_mut() {
                row.wait_raw_status = Some(raw);
                row.wait_outcome = Some(outcome);
            }
        }
    }
}

impl Trace {
    pub(super) fn child_observation_after_wait(
        &self,
        point: ProcessAssertionPoint,
    ) -> Result<(), Status> {
        let mut s = lock(&self.inner.state)?;
        let scenario = s.scenario.ok_or(Status::Invalid)?;
        if !scenario.assertion_child()
            || !scenario.blocks(point)
            || s.points.iter().any(|p| p.point == point)
        {
            return Err(Status::Invalid);
        }
        let sequence = s.points.len() as u64 + 1;
        s.points.push(ProcessAssertionCheckpoint {
            point,
            reached_at: Instant::now(),
            sequence,
        });
        Ok(())
    }
}

#[cfg(not(feature = "host_editor_process_assertions_v0_dev"))]
impl Trace {
    pub(super) fn process_started(&self) {}
    pub(super) fn process_forked(&self, _pid: u32) {
        self.forked();
    }
    pub(super) fn process_birth(&self, _birth: u64) {}
    pub(super) fn process_pidfd(&self, _id: u64) {}
    pub(super) fn process_wait(&self, _raw: i32, _outcome: ProcessWaitOutcome) {}
}
