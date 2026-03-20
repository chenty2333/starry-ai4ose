use alloc::sync::Arc;

use axerrno::{AxError, AxResult, LinuxError};
use axtask::current;
use starry_process::Pid;

use crate::{
    lab::{self, EventKind},
    task::{
        AsThread, get_process_data, get_process_group, register_process_group, register_session,
    },
};

fn resolve_setpgid_target(pid: Pid) -> AxResult<Arc<crate::task::ProcessData>> {
    let curr = current();
    let curr_proc = &curr.as_thread().proc_data.proc;
    let target_pid = if pid == 0 { curr_proc.pid() } else { pid };
    if target_pid == curr_proc.pid() {
        return Ok(curr.as_thread().proc_data.clone());
    }

    if curr_proc
        .children()
        .iter()
        .any(|child| child.pid() == target_pid)
    {
        get_process_data(target_pid)
    } else {
        Err(AxError::NoSuchProcess)
    }
}

pub fn sys_getsid(pid: Pid) -> AxResult<isize> {
    Ok(get_process_data(pid)?.proc.group().session().sid() as _)
}

pub fn sys_setsid() -> AxResult<isize> {
    let curr = current();
    let proc = &curr.as_thread().proc_data.proc;
    if proc.group().pgid() == proc.pid() {
        return Err(AxError::OperationNotPermitted);
    }

    if let Some((session, group)) = proc.create_session() {
        register_session(&session);
        register_process_group(&group);
        lab::emit(
            EventKind::SessionCreate,
            session.sid() as usize,
            group.pgid() as usize,
        );
        Ok(session.sid() as _)
    } else {
        Err(AxError::OperationNotPermitted)
    }
}

pub fn sys_getpgid(pid: Pid) -> AxResult<isize> {
    Ok(get_process_data(pid)?.proc.group().pgid() as _)
}

pub fn sys_setpgid(pid: Pid, pgid: Pid) -> AxResult<isize> {
    let curr = current();
    let curr_proc = &curr.as_thread().proc_data.proc;
    let proc_data = resolve_setpgid_target(pid)?;
    let proc = &proc_data.proc;
    let target_pid = proc.pid();
    let target_pgid = if pgid == 0 { target_pid } else { pgid };

    if target_pgid == 0 {
        return Err(AxError::from(LinuxError::EINVAL));
    }
    if !Arc::ptr_eq(&curr_proc.group().session(), &proc.group().session()) {
        return Err(AxError::OperationNotPermitted);
    }
    if proc.group().session().sid() == target_pid {
        return Err(AxError::OperationNotPermitted);
    }

    if target_pgid == proc.group().pgid() {
        return Ok(0);
    }

    if target_pgid == target_pid {
        if let Some(group) = proc.create_group() {
            register_process_group(&group);
        }
    } else {
        let group = get_process_group(target_pgid).map_err(|_| AxError::OperationNotPermitted)?;
        if !proc.move_to_group(&group) {
            return Err(AxError::OperationNotPermitted);
        }
    }

    lab::emit(
        EventKind::ProcessGroupSet,
        target_pid as usize,
        target_pgid as usize,
    );
    Ok(0)
}

// TODO: job control
