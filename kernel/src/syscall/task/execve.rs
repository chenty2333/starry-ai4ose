use alloc::{string::ToString, sync::Arc, vec::Vec};
use core::ffi::c_char;

use axerrno::{AxError, AxResult};
use axfs::FS_CONTEXT;
use axhal::uspace::UserContext;
use axtask::current;
use linux_raw_sys::general::{AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW};
use starry_vm::vm_load_until_nul;

use crate::{
    config::USER_HEAP_BASE,
    file::{FD_TABLE, resolve_at},
    mm::{load_user_app, vm_load_string},
    task::AsThread,
};

fn collect_string_array(ptr: *const *const c_char) -> AxResult<Vec<alloc::string::String>> {
    if ptr.is_null() {
        Ok(Vec::new())
    } else {
        vm_load_until_nul(ptr)?
            .into_iter()
            .map(vm_load_string)
            .collect()
    }
}

fn execve_common(
    uctx: &mut UserContext,
    path: alloc::string::String,
    args: Vec<alloc::string::String>,
    envs: Vec<alloc::string::String>,
) -> AxResult<isize> {
    debug!("execve <= path: {path:?}, args: {args:?}, envs: {envs:?}");

    let curr = current();
    let proc_data = &curr.as_thread().proc_data;

    if proc_data.proc.threads().len() > 1 {
        // TODO: handle multi-thread case
        error!("sys_execve: multi-thread not supported");
        return Err(AxError::WouldBlock);
    }

    let mut aspace = proc_data.aspace.lock();
    let (entry_point, user_stack_base) =
        load_user_app(&mut aspace, Some(path.as_str()), &args, &envs)?;
    drop(aspace);

    let loc = FS_CONTEXT.lock().resolve(&path)?;
    curr.set_name(loc.name());

    *proc_data.exe_path.write() = loc.absolute_path()?.to_string();
    *proc_data.cmdline.write() = Arc::new(args);

    proc_data.set_heap_top(USER_HEAP_BASE);

    *proc_data.signal.actions.lock() = Default::default();

    // Clear set_child_tid after exec since the original address is no longer valid
    curr.as_thread().set_clear_child_tid(0);

    // Close CLOEXEC file descriptors
    let mut fd_table = FD_TABLE.write();
    let cloexec_fds = fd_table
        .ids()
        .filter(|it| fd_table.get(*it).unwrap().cloexec)
        .collect::<Vec<_>>();
    for fd in cloexec_fds {
        fd_table.remove(fd);
    }
    drop(fd_table);

    uctx.set_ip(entry_point.as_usize());
    uctx.set_sp(user_stack_base.as_usize());
    Ok(0)
}

pub fn sys_execve(
    uctx: &mut UserContext,
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> AxResult<isize> {
    execve_common(
        uctx,
        vm_load_string(path)?,
        collect_string_array(argv)?,
        collect_string_array(envp)?,
    )
}

pub fn sys_execveat(
    uctx: &mut UserContext,
    dirfd: i32,
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    flags: i32,
) -> AxResult<isize> {
    let allowed_flags = (AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) as i32;
    if flags & !allowed_flags != 0 {
        return Err(AxError::InvalidInput);
    }

    let path = if path.is_null() {
        None
    } else {
        Some(vm_load_string(path)?)
    };
    let resolved = resolve_at(dirfd, path.as_deref(), flags as u32)?
        .into_file()
        .ok_or(AxError::BadFileDescriptor)?;
    let path = resolved.absolute_path()?.to_string();

    execve_common(
        uctx,
        path,
        collect_string_array(argv)?,
        collect_string_array(envp)?,
    )
}
