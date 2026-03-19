use alloc::{borrow::Cow, boxed::Box, sync::Arc};
use core::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::Context,
};

use axerrno::AxResult;
use axpoll::PollSet;
use kspin::SpinNoPreempt;
use ringbuf::{
    Cons, HeapRb, Prod,
    traits::{Consumer, Producer},
};

use super::{
    Tty,
    terminal::{
        Terminal,
        ldisc::{ProcessMode, TtyConfig, TtyRead, TtyWrite},
    },
};
use crate::file::{File, FileLike, IoDst, IoSrc, Kstat};

const PTY_BUF_SIZE: usize = 4096;

pub type PtyDriver = Tty<PtyReader, PtyWriter>;

type Buffer = Arc<HeapRb<u8>>;

struct PtyEndpoint {
    open_files: AtomicUsize,
    ever_opened: AtomicBool,
    poll_close: PollSet,
}

impl PtyEndpoint {
    fn new() -> Self {
        Self {
            open_files: AtomicUsize::new(0),
            ever_opened: AtomicBool::new(false),
            poll_close: PollSet::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> PtyOpenGuard {
        self.ever_opened.store(true, Ordering::Release);
        self.open_files.fetch_add(1, Ordering::AcqRel);
        PtyOpenGuard(self.clone())
    }

    fn is_hung_up(&self) -> bool {
        self.ever_opened.load(Ordering::Acquire)
            && self.open_files.load(Ordering::Acquire) == 0
    }
}

pub struct PtyOpenGuard(Arc<PtyEndpoint>);

impl Drop for PtyOpenGuard {
    fn drop(&mut self) {
        if self.0.open_files.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.poll_close.wake();
        }
    }
}

pub struct PtyReader(Cons<Buffer>, Arc<PtyEndpoint>);

impl PtyReader {
    fn new(buffer: Buffer, peer: Arc<PtyEndpoint>) -> Self {
        Self(Cons::new(buffer), peer)
    }
}

impl TtyRead for PtyReader {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        self.0.pop_slice(buf)
    }

    fn peer_closed(&self) -> bool {
        self.1.is_hung_up()
    }

    fn register_close_waker(&self, waker: &core::task::Waker) {
        self.1.poll_close.register(waker);
    }
}

#[derive(Clone)]
pub struct PtyWriter(Arc<SpinNoPreempt<Prod<Buffer>>>, Arc<PollSet>, Arc<PtyEndpoint>);

impl PtyWriter {
    fn new(buffer: Buffer, poll_rx: Arc<PollSet>, this: Arc<PtyEndpoint>) -> Self {
        Self(Arc::new(SpinNoPreempt::new(Prod::new(buffer))), poll_rx, this)
    }

    fn open_guard(&self) -> PtyOpenGuard {
        self.2.acquire()
    }
}

impl TtyWrite for PtyWriter {
    fn write(&self, buf: &[u8]) {
        let read = self.0.lock().push_slice(buf);
        self.1.wake();
        if read < buf.len() {
            warn!("Discarding {} bytes written to pty", buf.len() - read);
        }
    }
}

impl Tty<PtyReader, PtyWriter> {
    pub fn open_guard(&self) -> PtyOpenGuard {
        self.writer.open_guard()
    }
}

pub struct OpenedPtyFile {
    inner: File,
    _guard: PtyOpenGuard,
}

impl OpenedPtyFile {
    pub fn new(inner: File, guard: PtyOpenGuard) -> Self {
        Self {
            inner,
            _guard: guard,
        }
    }
}

impl FileLike for OpenedPtyFile {
    fn read(&self, dst: &mut IoDst) -> AxResult<usize> {
        self.inner.read(dst)
    }

    fn write(&self, src: &mut IoSrc) -> AxResult<usize> {
        self.inner.write(src)
    }

    fn stat(&self) -> AxResult<Kstat> {
        self.inner.stat()
    }

    fn path(&self) -> Cow<'_, str> {
        self.inner.path()
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> AxResult<usize> {
        self.inner.ioctl(cmd, arg)
    }

    fn nonblocking(&self) -> bool {
        self.inner.nonblocking()
    }

    fn set_nonblocking(&self, nonblocking: bool) -> AxResult {
        self.inner.set_nonblocking(nonblocking)
    }
}

impl axpoll::Pollable for OpenedPtyFile {
    fn poll(&self) -> axpoll::IoEvents {
        self.inner.poll()
    }

    fn register(&self, context: &mut Context<'_>, events: axpoll::IoEvents) {
        self.inner.register(context, events);
    }
}

pub(crate) fn create_pty_pair() -> (Arc<PtyDriver>, Arc<PtyDriver>) {
    let master_to_slave = Arc::new(HeapRb::new(PTY_BUF_SIZE));
    let slave_to_master = Arc::new(HeapRb::new(PTY_BUF_SIZE));
    let poll_rx_slave = Arc::new(PollSet::new());
    let poll_rx_master = Arc::new(PollSet::new());
    let master_endpoint = Arc::new(PtyEndpoint::new());
    let slave_endpoint = Arc::new(PtyEndpoint::new());

    let terminal = Arc::new(Terminal::default());

    let master = Tty::new(
        terminal.clone(),
        TtyConfig {
            reader: PtyReader::new(slave_to_master.clone(), slave_endpoint.clone()),
            writer: PtyWriter::new(
                master_to_slave.clone(),
                poll_rx_slave.clone(),
                master_endpoint.clone(),
            ),
            process_mode: ProcessMode::None(poll_rx_master.clone()),
        },
    );

    let slave = Tty::new(
        terminal,
        TtyConfig {
            reader: PtyReader::new(master_to_slave, master_endpoint),
            writer: PtyWriter::new(slave_to_master, poll_rx_master, slave_endpoint),
            process_mode: ProcessMode::External(Box::new(move |waker| {
                poll_rx_slave.register(&waker)
            })),
        },
    );

    (master, slave)
}
