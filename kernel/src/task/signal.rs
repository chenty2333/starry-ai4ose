use core::{
    future::poll_fn,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
};

use axerrno::{AxError, AxResult};
use axhal::uspace::UserContext;
use axtask::{
    TaskInner, current,
    future::{block_on, interruptible},
};
use starry_process::Pid;
use starry_signal::{SignalInfo, SignalOSAction, SignalSet, Signo};

use super::{
    AsThread, Thread, do_exit, get_process_data, get_process_group, get_task,
    interrupt_process_threads,
};
use crate::lab::{self, EventKind};

fn signal_action_code(action: SignalOSAction) -> usize {
    match action {
        SignalOSAction::Terminate => 1,
        SignalOSAction::CoreDump => 2,
        SignalOSAction::Stop => 3,
        SignalOSAction::Continue => 4,
        SignalOSAction::Handler => 5,
    }
}

fn notify_parent_of_child_state_change(thr: &Thread) {
    let proc = &thr.proc_data.proc;
    let Some(parent) = proc.parent() else {
        return;
    };

    let _ = send_signal_to_process(parent.pid(), Some(SignalInfo::new_kernel(Signo::SIGCHLD)));
    if let Ok(parent_data) = get_process_data(parent.pid()) {
        parent_data.child_exit_event.wake();
    }
}

fn stop_current_process(thr: &Thread, signo: Signo) {
    let changed = thr.proc_data.record_stop(signo);
    thr.proc_data.stop_event.wake();
    interrupt_process_threads(&thr.proc_data.proc);
    if changed {
        notify_parent_of_child_state_change(thr);
    }
}

fn continue_current_process(thr: &Thread) {
    let changed = thr.proc_data.record_continue();
    thr.proc_data.stop_event.wake();
    interrupt_process_threads(&thr.proc_data.proc);
    if changed {
        notify_parent_of_child_state_change(thr);
    }
}

pub fn check_signals(
    thr: &Thread,
    uctx: &mut UserContext,
    restore_blocked: Option<SignalSet>,
) -> bool {
    let Some((sig, os_action)) = thr.signal.check_signals(uctx, restore_blocked) else {
        return false;
    };

    let signo = sig.signo();
    lab::emit(
        EventKind::SignalHandle,
        signo as usize,
        signal_action_code(os_action),
    );
    if signo == Signo::SIGCONT {
        continue_current_process(thr);
    }
    match os_action {
        SignalOSAction::Terminate => {
            do_exit(signo as i32, true);
        }
        SignalOSAction::CoreDump => {
            // TODO: implement core dump
            do_exit(128 + signo as i32, true);
        }
        SignalOSAction::Stop => {
            stop_current_process(thr, signo);
        }
        SignalOSAction::Continue => {
            // `SIGCONT` has already resumed the process above. Any user
            // handler frame has been prepared by `starry-signal`.
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

pub fn wait_if_stopped(thr: &Thread, uctx: &mut UserContext) {
    while thr.proc_data.is_stopped() && !thr.pending_exit() {
        if check_signals(thr, uctx, None) {
            continue;
        }

        let _ = block_on(interruptible(poll_fn(|cx| {
            if !thr.proc_data.is_stopped() || thr.pending_exit() {
                return Poll::Ready(());
            }
            thr.proc_data.stop_event.register(cx.waker());
            Poll::Pending
        })));
    }
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
    lab::emit(
        EventKind::SignalSend,
        sig.signo() as usize,
        task.id().as_u64() as usize,
    );
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
        info!("Send signal {signo:?} to process {pid}");
        lab::emit(EventKind::SignalSend, signo as usize, pid as usize);
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
    lab::emit(
        EventKind::SignalSend,
        signo as usize,
        proc_data.proc.pid() as usize,
    );
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
