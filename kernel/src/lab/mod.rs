#[cfg(feature = "lab")]
mod imp {
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use axhal::time::monotonic_time;
    use spin::Mutex;

    const TRACE_CAPACITY: usize = 4096;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum EventKind {
        #[default]
        None,
        SysEnter,
        SysExit,
        PageFault,
        SignalSend,
        SignalHandle,
        FdOpen,
        FdClose,
        PollSleep,
        PollWake,
        TaskExit,
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct TraceEvent {
        pub seq: u64,
        pub time_ns: u64,
        pub tid: u64,
        pub kind: EventKind,
        pub arg0: usize,
        pub arg1: usize,
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct LabStats {
        pub emitted: u64,
        pub overwritten: u64,
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct LastFault {
        pub tid: u64,
        pub addr: usize,
        pub flags: usize,
    }

    #[derive(Debug)]
    struct TraceBuffer {
        events: [TraceEvent; TRACE_CAPACITY],
        head: usize,
        len: usize,
    }

    impl TraceBuffer {
        const fn new() -> Self {
            Self {
                events: [TraceEvent {
                    seq: 0,
                    time_ns: 0,
                    tid: 0,
                    kind: EventKind::None,
                    arg0: 0,
                    arg1: 0,
                }; TRACE_CAPACITY],
                head: 0,
                len: 0,
            }
        }

        fn push(&mut self, event: TraceEvent) -> bool {
            if self.len == TRACE_CAPACITY {
                self.events[self.head] = event;
                self.head = (self.head + 1) % TRACE_CAPACITY;
                true
            } else {
                let idx = (self.head + self.len) % TRACE_CAPACITY;
                self.events[idx] = event;
                self.len += 1;
                false
            }
        }

        fn snapshot(&self) -> Vec<TraceEvent> {
            let mut out = Vec::with_capacity(self.len);
            for i in 0..self.len {
                let idx = (self.head + i) % TRACE_CAPACITY;
                out.push(self.events[idx]);
            }
            out
        }
    }

    static TRACE: Mutex<TraceBuffer> = Mutex::new(TraceBuffer::new());
    static ENABLED: AtomicBool = AtomicBool::new(true);
    static EMITTED: AtomicU64 = AtomicU64::new(0);
    static OVERWRITTEN: AtomicU64 = AtomicU64::new(0);
    static LAST_FAULT: Mutex<Option<LastFault>> = Mutex::new(None);

    fn current_tid() -> u64 {
        axtask::current().id().as_u64()
    }

    pub fn enabled() -> bool {
        ENABLED.load(Ordering::Relaxed)
    }

    pub fn set_enabled(enabled: bool) {
        ENABLED.store(enabled, Ordering::Relaxed);
    }

    pub fn emit(kind: EventKind, arg0: usize, arg1: usize) {
        if !enabled() {
            return;
        }
        let seq = EMITTED.fetch_add(1, Ordering::Relaxed) + 1;
        let event = TraceEvent {
            seq,
            time_ns: monotonic_time().as_nanos() as u64,
            tid: current_tid(),
            kind,
            arg0,
            arg1,
        };
        if TRACE.lock().push(event) {
            OVERWRITTEN.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_fault(addr: usize, flags: usize) {
        if !enabled() {
            return;
        }
        *LAST_FAULT.lock() = Some(LastFault {
            tid: current_tid(),
            addr,
            flags,
        });
        emit(EventKind::PageFault, addr, flags);
    }

    pub fn stats() -> LabStats {
        LabStats {
            emitted: EMITTED.load(Ordering::Relaxed),
            overwritten: OVERWRITTEN.load(Ordering::Relaxed),
        }
    }

    pub fn last_fault() -> Option<LastFault> {
        *LAST_FAULT.lock()
    }

    pub fn trace_snapshot() -> Vec<TraceEvent> {
        TRACE.lock().snapshot()
    }

    pub fn clear() {
        *TRACE.lock() = TraceBuffer::new();
        *LAST_FAULT.lock() = None;
        EMITTED.store(0, Ordering::Relaxed);
        OVERWRITTEN.store(0, Ordering::Relaxed);
    }
}

#[cfg(not(feature = "lab"))]
mod imp {
    use alloc::vec::Vec;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum EventKind {
        #[default]
        None,
        SysEnter,
        SysExit,
        PageFault,
        SignalSend,
        SignalHandle,
        FdOpen,
        FdClose,
        PollSleep,
        PollWake,
        TaskExit,
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct TraceEvent {
        pub seq: u64,
        pub time_ns: u64,
        pub tid: u64,
        pub kind: EventKind,
        pub arg0: usize,
        pub arg1: usize,
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct LabStats {
        pub emitted: u64,
        pub overwritten: u64,
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct LastFault {
        pub tid: u64,
        pub addr: usize,
        pub flags: usize,
    }

    pub fn enabled() -> bool {
        false
    }

    pub fn set_enabled(_enabled: bool) {}

    pub fn emit(_kind: EventKind, _arg0: usize, _arg1: usize) {}

    pub fn record_fault(_addr: usize, _flags: usize) {}

    pub fn stats() -> LabStats {
        LabStats::default()
    }

    pub fn last_fault() -> Option<LastFault> {
        None
    }

    pub fn trace_snapshot() -> Vec<TraceEvent> {
        Vec::new()
    }

    pub fn clear() {}
}

pub use imp::*;

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::None => "None",
            EventKind::SysEnter => "SysEnter",
            EventKind::SysExit => "SysExit",
            EventKind::PageFault => "PageFault",
            EventKind::SignalSend => "SignalSend",
            EventKind::SignalHandle => "SignalHandle",
            EventKind::FdOpen => "FdOpen",
            EventKind::FdClose => "FdClose",
            EventKind::PollSleep => "PollSleep",
            EventKind::PollWake => "PollWake",
            EventKind::TaskExit => "TaskExit",
        }
    }
}
