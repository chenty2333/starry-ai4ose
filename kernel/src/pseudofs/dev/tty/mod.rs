mod ntty;
mod ptm;
mod pts;
mod pty;
mod terminal;

use alloc::sync::{Arc, Weak};
use core::{any::Any, ops::Deref, sync::atomic::Ordering, task::Context};

use axerrno::{AxError, AxResult};
use axfs_ng_vfs::NodeFlags;
use axpoll::{IoEvents, Pollable};
use axsync::Mutex;
use axtask::{
    current,
    future::{block_on, poll_io},
};
use starry_process::Process;
use starry_signal::{SignalInfo, Signo};
use starry_vm::{VmMutPtr, VmPtr};

use self::terminal::{
    Terminal, WindowSize,
    ldisc::{LineDiscipline, ProcessMode, TtyConfig, TtyRead, TtyWrite},
    termios::{Termios, Termios2},
};
pub use self::{
    ntty::{N_TTY, NTtyDriver},
    ptm::Ptmx,
    pts::PtsDir,
    pty::{OpenedPtyFile, PtyDriver},
};
use crate::{
    lab::{self, EventKind, TTY_CTL_TIOCSCTTY, TTY_CTL_TIOCNOTTY, TTY_CTL_TIOCSPGRP},
    pseudofs::{DeviceOps, SimpleFs},
    task::{AsThread, get_process_group, send_signal_to_process_group},
};

pub fn create_pty_master(fs: Arc<SimpleFs>) -> AxResult<Arc<PtyDriver>> {
    let (master, slave) = pty::create_pty_pair();
    pts::add_slave(fs, slave)?;
    Ok(master)
}

/// Tty device
pub struct Tty<R, W> {
    this: Weak<Self>,
    terminal: Arc<Terminal>,
    ldisc: Mutex<LineDiscipline<R, W>>,
    writer: W,
    is_ptm: bool,
}

impl<R: TtyRead, W: TtyWrite + Clone> Tty<R, W> {
    fn new(terminal: Arc<Terminal>, config: TtyConfig<R, W>) -> Arc<Self> {
        let writer = config.writer.clone();
        let is_ptm = matches!(&config.process_mode, ProcessMode::None(_));
        let ldisc = Mutex::new(LineDiscipline::new(terminal.clone(), config));
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            terminal,
            ldisc,
            writer,
            is_ptm,
        })
    }
}

impl<R: TtyRead, W: TtyWrite> Tty<R, W> {
    pub fn bind_to(self: &Arc<Self>, proc: &Process) -> AxResult<()> {
        let pg = proc.group();
        let session = pg.session();
        if session.sid() != proc.pid() {
            return Err(AxError::OperationNotPermitted);
        }
        let term: Arc<dyn Any + Send + Sync> = self.clone();
        if let Some(existing) = session.terminal() {
            if !Arc::ptr_eq(&existing, &term) {
                return Err(AxError::OperationNotPermitted);
            }
        } else {
            if let Some(owner) = self.terminal.job_control.session()
                && !Arc::ptr_eq(&owner, &session)
            {
                return Err(AxError::OperationNotPermitted);
            }
            if !session.set_terminal_with(|| term.clone()) {
                return Err(AxError::OperationNotPermitted);
            }
        }
        self.terminal.job_control.set_session(&session);
        self.terminal.job_control.set_foreground(&pg)?;
        Ok(())
    }

    pub fn pty_number(&self) -> u32 {
        self.terminal.pty_number.load(Ordering::Acquire)
    }

    fn signal_background_tty_access(&self, signo: Signo) -> AxResult<usize> {
        let curr = current();
        let pgid = curr.as_thread().proc_data.proc.group().pgid();
        send_signal_to_process_group(pgid, Some(SignalInfo::new_kernel(signo)))?;
        Err(AxError::Interrupted)
    }
}

impl<R: TtyRead, W: TtyWrite> DeviceOps for Tty<R, W> {
    fn read_at(&self, buf: &mut [u8], _offset: u64) -> AxResult<usize> {
        if self.is_ptm {
            block_on(poll_io(self, IoEvents::IN, false, || self.ldisc.lock().read(buf)))
        } else {
            block_on(poll_io(self, IoEvents::IN, false, || {
                if self.terminal.job_control.current_in_foreground() {
                    self.ldisc.lock().read(buf)
                } else {
                    self.signal_background_tty_access(Signo::SIGTTIN)
                }
            }))
        }
    }

    fn write_at(&self, buf: &[u8], _offset: u64) -> AxResult<usize> {
        if !self.is_ptm {
            let termios = self.terminal.load_termios();
            if termios.tostop() && !self.terminal.job_control.current_in_foreground() {
                return self.signal_background_tty_access(Signo::SIGTTOU);
            }
        }
        self.writer.write(buf);
        Ok(buf.len())
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> AxResult<usize> {
        use linux_raw_sys::ioctl::*;
        match cmd {
            TCGETS => {
                (arg as *mut Termios).vm_write(*self.terminal.termios.lock().as_ref().deref())?;
            }
            TCGETS2 => {
                (arg as *mut Termios2).vm_write(*self.terminal.termios.lock().as_ref())?;
            }
            TCSETS | TCSETSF | TCSETSW => {
                // TODO: drain output?
                *self.terminal.termios.lock() =
                    Arc::new(Termios2::new((arg as *const Termios).vm_read()?));
                if cmd == TCSETSF {
                    self.ldisc.lock().drain_input();
                }
            }
            TCSETS2 | TCSETSF2 | TCSETSW2 => {
                // TODO: drain output?
                *self.terminal.termios.lock() = Arc::new((arg as *const Termios2).vm_read()?);
                if cmd == TCSETSF2 {
                    self.ldisc.lock().drain_input();
                }
            }
            TIOCGPGRP => {
                let foreground = self
                    .terminal
                    .job_control
                    .foreground()
                    .ok_or(AxError::NoSuchProcess)?;
                (arg as *mut u32).vm_write(foreground.pgid())?;
            }
            TIOCSPGRP => {
                let curr = current();
                let pgid = (arg as *const u32).vm_read()?;
                let pg = get_process_group(pgid)?;
                if !Arc::ptr_eq(&curr.as_thread().proc_data.proc.group().session(), &pg.session()) {
                    return Err(AxError::OperationNotPermitted);
                }
                if !self
                    .terminal
                    .job_control
                    .session()
                    .is_some_and(|session| Arc::ptr_eq(&session, &pg.session()))
                {
                    return Err(AxError::OperationNotPermitted);
                }
                self.terminal
                    .job_control
                    .set_foreground(&pg)?;
                lab::emit(EventKind::TtyCtl, TTY_CTL_TIOCSPGRP, pgid as usize);
            }
            TIOCGWINSZ => {
                (arg as *mut WindowSize).vm_write(*self.terminal.window_size.lock())?;
            }
            TIOCSWINSZ => {
                *self.terminal.window_size.lock() = (arg as *const WindowSize).vm_read()?;
            }
            TIOCSPTLCK => {}
            TIOCGPTN => {
                (arg as *mut u32).vm_write(self.pty_number())?;
            }
            TIOCSCTTY => {
                let curr = current();
                let proc = &curr.as_thread().proc_data.proc;
                if let Some(owner) = self.terminal.job_control.session()
                    && !Arc::ptr_eq(&owner, &proc.group().session())
                {
                    return Err(AxError::OperationNotPermitted);
                }
                self.this.upgrade().unwrap().bind_to(proc)?;
                lab::emit(
                    EventKind::TtyCtl,
                    TTY_CTL_TIOCSCTTY,
                    proc.group().session().sid() as usize,
                );
            }
            TIOCNOTTY => {
                let curr = current();
                let proc = &curr.as_thread().proc_data.proc;
                let session = proc.group().session();
                let term = self.this.upgrade().unwrap();
                let term_any: Arc<dyn Any + Send + Sync> = term.clone();
                let was_session_leader = session.sid() == proc.pid();
                let foreground = self.terminal.job_control.foreground();

                if session.unset_terminal(&term_any) {
                    self.terminal.job_control.clear_session(&session);
                    lab::emit(EventKind::TtyCtl, TTY_CTL_TIOCNOTTY, session.sid() as usize);

                    if was_session_leader && let Some(pg) = foreground {
                        let _ = send_signal_to_process_group(
                            pg.pgid(),
                            Some(SignalInfo::new_kernel(Signo::SIGHUP)),
                        );
                        let _ = send_signal_to_process_group(
                            pg.pgid(),
                            Some(SignalInfo::new_kernel(Signo::SIGCONT)),
                        );
                    }
                }
            }
            _ => return Err(AxError::NotATty),
        }
        Ok(0)
    }

    fn as_pollable(&self) -> Option<&dyn Pollable> {
        Some(self)
    }

    /// Casts the device operations to a dynamic type.
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn flags(&self) -> NodeFlags {
        NodeFlags::NON_CACHEABLE | NodeFlags::STREAM
    }
}

impl<R: TtyRead, W: TtyWrite> Pollable for Tty<R, W> {
    fn poll(&self) -> IoEvents {
        let mut events = IoEvents::OUT | self.terminal.job_control.poll();
        let mut ldisc = self.ldisc.lock();
        if self.is_ptm || events.contains(IoEvents::IN) {
            events.set(IoEvents::IN, ldisc.poll_read());
        }
        events.set(IoEvents::HUP, ldisc.poll_hup());
        events
    }

    fn register(&self, context: &mut Context<'_>, events: IoEvents) {
        if !self.is_ptm {
            self.terminal.job_control.register(context, events);
        }
        if events.intersects(IoEvents::IN | IoEvents::HUP) {
            self.ldisc.lock().register_rx_waker(context.waker());
        }
    }
}

pub struct CurrentTty;
impl DeviceOps for CurrentTty {
    fn read_at(&self, _buf: &mut [u8], _offset: u64) -> AxResult<usize> {
        unreachable!()
    }

    fn write_at(&self, _buf: &[u8], _offset: u64) -> AxResult<usize> {
        Ok(0)
    }

    fn ioctl(&self, _cmd: u32, _arg: usize) -> AxResult<usize> {
        unreachable!()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
