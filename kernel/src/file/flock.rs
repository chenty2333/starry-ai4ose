use alloc::collections::{BTreeMap, BTreeSet};
use core::{future::poll_fn, task::Poll};

use axerrno::{AxError, AxResult};
use axpoll::PollSet;
use axtask::future::block_on;
use spin::Mutex;
use starry_process::Pid;

/// Inode identity: (device, inode number).
type InodeId = (u64, u64);

enum FlockState {
    /// One or more processes hold shared (read) locks.
    Shared(BTreeSet<Pid>),
    /// Exactly one process holds an exclusive (write) lock.
    Exclusive(Pid),
}

struct FlockTableInner {
    locks: BTreeMap<InodeId, FlockState>,
    /// Woken whenever any lock is released, so blocked acquirers can retry.
    waiters: PollSet,
}

static FLOCK_TABLE: Mutex<FlockTableInner> = Mutex::new(FlockTableInner {
    locks: BTreeMap::new(),
    waiters: PollSet::new(),
});

/// Attempt to acquire a shared lock. Returns `true` on success.
fn try_lock_shared(id: InodeId, pid: Pid) -> bool {
    let mut table = FLOCK_TABLE.lock();
    match table.locks.get_mut(&id) {
        None => {
            let mut holders = BTreeSet::new();
            holders.insert(pid);
            table.locks.insert(id, FlockState::Shared(holders));
            true
        }
        Some(FlockState::Shared(holders)) => {
            holders.insert(pid);
            true
        }
        Some(FlockState::Exclusive(owner)) if *owner == pid => {
            // Downgrade from exclusive to shared.
            let mut holders = BTreeSet::new();
            holders.insert(pid);
            table.locks.insert(id, FlockState::Shared(holders));
            table.waiters.wake();
            true
        }
        Some(FlockState::Exclusive(_)) => false,
    }
}

/// Attempt to acquire an exclusive lock. Returns `true` on success.
fn try_lock_exclusive(id: InodeId, pid: Pid) -> bool {
    let mut table = FLOCK_TABLE.lock();
    match table.locks.get_mut(&id) {
        None => {
            table.locks.insert(id, FlockState::Exclusive(pid));
            true
        }
        Some(FlockState::Exclusive(owner)) if *owner == pid => {
            // Already exclusively locked by this process.
            true
        }
        Some(FlockState::Shared(holders)) if holders.len() == 1 && holders.contains(&pid) => {
            // Upgrade from shared to exclusive (only holder).
            table.locks.insert(id, FlockState::Exclusive(pid));
            true
        }
        _ => false,
    }
}

/// Release the lock held by `pid` on the given inode.
pub fn flock_unlock(id: InodeId, pid: Pid) {
    let mut table = FLOCK_TABLE.lock();
    let should_remove = match table.locks.get_mut(&id) {
        Some(FlockState::Shared(holders)) => {
            holders.remove(&pid);
            holders.is_empty()
        }
        Some(FlockState::Exclusive(owner)) if *owner == pid => true,
        _ => false,
    };
    if should_remove {
        table.locks.remove(&id);
    }
    table.waiters.wake();
}

/// Acquire a shared lock, blocking if necessary.
fn lock_shared_blocking(id: InodeId, pid: Pid) -> AxResult<()> {
    block_on(poll_fn(|cx| {
        if try_lock_shared(id, pid) {
            Poll::Ready(Ok(()))
        } else {
            FLOCK_TABLE.lock().waiters.register(cx.waker());
            // Re-check after registration to avoid missed wake-ups.
            if try_lock_shared(id, pid) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }))
}

/// Acquire an exclusive lock, blocking if necessary.
fn lock_exclusive_blocking(id: InodeId, pid: Pid) -> AxResult<()> {
    block_on(poll_fn(|cx| {
        if try_lock_exclusive(id, pid) {
            Poll::Ready(Ok(()))
        } else {
            FLOCK_TABLE.lock().waiters.register(cx.waker());
            // Re-check after registration to avoid missed wake-ups.
            if try_lock_exclusive(id, pid) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }))
}

/// Perform a flock operation on the given inode identity.
///
/// `operation` uses Linux LOCK_* constants:
/// - `LOCK_SH` (1): Shared lock
/// - `LOCK_EX` (2): Exclusive lock
/// - `LOCK_UN` (8): Unlock
/// - `LOCK_NB` (4): Non-blocking (OR'd with SH or EX)
pub fn do_flock(id: InodeId, pid: Pid, operation: i32) -> AxResult<()> {
    const LOCK_SH: i32 = 1;
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    const LOCK_UN: i32 = 8;

    let non_blocking = (operation & LOCK_NB) != 0;
    let op = operation & !LOCK_NB;

    match op {
        LOCK_SH => {
            if non_blocking {
                if try_lock_shared(id, pid) {
                    Ok(())
                } else {
                    Err(AxError::WouldBlock)
                }
            } else {
                lock_shared_blocking(id, pid)
            }
        }
        LOCK_EX => {
            if non_blocking {
                if try_lock_exclusive(id, pid) {
                    Ok(())
                } else {
                    Err(AxError::WouldBlock)
                }
            } else {
                lock_exclusive_blocking(id, pid)
            }
        }
        LOCK_UN => {
            flock_unlock(id, pid);
            Ok(())
        }
        _ => Err(AxError::InvalidInput),
    }
}
