use core::{
    future::poll_fn,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
};

use axerrno::{AxError, AxResult};
use axhal::uspace::UserContext;
use axtask::{
    TaskInner, current,
    future::block_on,
};
use starry_process::Pid;
use starry_signal::{SignalInfo, SignalOSAction, SignalSet, Signo};

use super::{AsThread, ProcessData, Thread, do_exit, get_process_data, get_process_group, get_task};

pub fn check_signals(
    thr: &Thread,
    uctx: &mut UserContext,
    restore_blocked: Option<SignalSet>,
) -> bool {
    let Some((sig, os_action)) = thr.signal.check_signals(uctx, restore_blocked) else {
        return false;
    };

    let signo = sig.signo();
    match os_action {
        SignalOSAction::Terminate => {
            do_exit(signo as i32, true);
        }
        SignalOSAction::CoreDump => {
            if let Err(e) = super::coredump::generate_core_dump(thr, uctx, signo as u8) {
                warn!("Core dump failed: {e:?}");
            }
            do_exit((signo as i32) | 0x80, true);
        }
        SignalOSAction::Stop => {
            do_stop(thr, signo as u8);
        }
        SignalOSAction::Continue => {
            do_continue(&thr.proc_data);
        }
        SignalOSAction::Handler => {
            // do nothing
        }
    }
    true
}

static BLOCK_NEXT_SIGNAL_CHECK: AtomicBool = AtomicBool::new(false);

pub fn block_next_signal() {
    BLOCK_NEXT_SIGNAL_CHECK.store(true, Ordering::SeqCst);
}

pub fn unblock_next_signal() -> bool {
    BLOCK_NEXT_SIGNAL_CHECK.swap(false, Ordering::SeqCst)
}

pub fn with_blocked_signals<R>(
    blocked: Option<SignalSet>,
    f: impl FnOnce() -> AxResult<R>,
) -> AxResult<R> {
    let curr = current();
    let sig = &curr.as_thread().signal;

    let old_blocked = blocked.map(|set| sig.set_blocked(set));
    f().inspect(|_| {
        if let Some(old) = old_blocked {
            sig.set_blocked(old);
        }
    })
}

pub(super) fn send_signal_thread_inner(task: &TaskInner, thr: &Thread, sig: SignalInfo) {
    if thr.signal.send_signal(sig) {
        task.interrupt();
    }
}

/// Sends a signal to a thread.
pub fn send_signal_to_thread(tgid: Option<Pid>, tid: Pid, sig: Option<SignalInfo>) -> AxResult<()> {
    let task = get_task(tid)?;
    let thread = task.try_as_thread().ok_or(AxError::OperationNotPermitted)?;
    if tgid.is_some_and(|tgid| thread.proc_data.proc.pid() != tgid) {
        return Err(AxError::NoSuchProcess);
    }

    if let Some(sig) = sig {
        info!("Send signal {:?} to thread {}", sig.signo(), tid);
        send_signal_thread_inner(&task, thread, sig);
    }

    Ok(())
}

/// Sends a signal to a process.
pub fn send_signal_to_process(pid: Pid, sig: Option<SignalInfo>) -> AxResult<()> {
    let proc_data = get_process_data(pid)?;

    if let Some(sig) = sig {
        let signo = sig.signo();

        // POSIX: SIGCONT always resumes a stopped process, regardless of disposition.
        if signo == Signo::SIGCONT {
            do_continue(&proc_data);
        }

        info!("Send signal {signo:?} to process {pid}");
        if let Some(tid) = proc_data.signal.send_signal(sig)
            && let Ok(task) = get_task(tid)
        {
            task.interrupt();
        }
    }

    Ok(())
}

/// Sends a signal to a process group.
pub fn send_signal_to_process_group(pgid: Pid, sig: Option<SignalInfo>) -> AxResult<()> {
    let pg = get_process_group(pgid)?;

    if let Some(sig) = sig {
        info!("Send signal {:?} to process group {}", sig.signo(), pgid);
        for proc in pg.processes() {
            send_signal_to_process(proc.pid(), Some(sig.clone()))?;
        }
    }

    Ok(())
}

/// Sends a fatal signal to the current process.
pub fn raise_signal_fatal(sig: SignalInfo) -> AxResult<()> {
    let curr = current();
    let proc_data = &curr.as_thread().proc_data;

    let signo = sig.signo();
    info!("Send fatal signal {signo:?} to the current process");
    if let Some(tid) = proc_data.signal.send_signal(sig)
        && let Ok(task) = get_task(tid)
    {
        task.interrupt();
    } else {
        // No task wants to handle the signal, abort the task
        do_exit(signo as i32, true);
    }

    Ok(())
}

/// Stops the current process (all threads) due to a stop signal.
fn do_stop(thr: &Thread, signo: u8) {
    let proc_data = &thr.proc_data;

    // Ignore if already stopped.
    if proc_data.is_stopped() {
        return;
    }

    info!("Stopping process {} by signal {}", proc_data.proc.pid(), signo);
    proc_data.set_stopped(signo);

    // Notify parent process.
    notify_parent_stop_continue(proc_data);

    // Interrupt all sibling threads so they notice the stopped flag.
    let curr_tid = current().id().as_u64() as Pid;
    for tid in proc_data.proc.threads() {
        if tid != curr_tid {
            if let Ok(task) = get_task(tid) {
                task.interrupt();
            }
        }
    }

    // Block this thread until the process is continued.
    wait_if_stopped(proc_data);
}

/// Continues a stopped process.
fn do_continue(proc_data: &ProcessData) {
    if proc_data.is_stopped() {
        info!("Continuing process {}", proc_data.proc.pid());
        proc_data.set_continued();
        notify_parent_stop_continue(proc_data);
    }
}

/// Blocks the current thread while the process is in the stopped state.
///
/// Called from `check_signals` (the thread that received the stop signal)
/// and from the user task main loop (sibling threads).
pub fn wait_if_stopped(proc_data: &ProcessData) {
    while proc_data.is_stopped() {
        block_on(poll_fn(|cx| {
            if !proc_data.is_stopped() {
                Poll::Ready(())
            } else {
                proc_data.stop_event.register(cx.waker());
                // Re-check after registration to avoid missed wake-ups.
                if !proc_data.is_stopped() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }
        }));
    }
}

/// Sends SIGCHLD to the parent and wakes its child_exit_event.
fn notify_parent_stop_continue(proc_data: &ProcessData) {
    let process = &proc_data.proc;
    if let Some(parent) = process.parent() {
        let _ = send_signal_to_process(
            parent.pid(),
            Some(SignalInfo::new_kernel(Signo::SIGCHLD)),
        );
        if let Ok(parent_data) = get_process_data(parent.pid()) {
            parent_data.child_exit_event.wake();
        }
    }
}
