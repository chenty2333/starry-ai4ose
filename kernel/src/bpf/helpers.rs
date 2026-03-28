//! BPF helper function dispatch table.
//!
//! Provides the runtime helper functions that BPF programs invoke via the
//! `CALL` instruction. Each helper has a numeric ID matching the Linux kernel's
//! `bpf_func_id` enum.

use alloc::{sync::Arc, vec::Vec};

use axhal::time::monotonic_time_nanos;
use axtask::current;

use super::{defs::*, map::BpfMap};
use crate::task::AsThread;

/// Runtime context passed to helper functions, providing access to maps and
/// scratch buffers.
pub struct HelperContext<'a> {
    /// Maps referenced by the running program.
    pub maps: &'a [Arc<dyn BpfMap>],
    /// Scratch buffer for map_lookup_elem return values. The helper writes the
    /// looked-up value here and returns a pointer into this buffer.
    pub scratch: &'a mut Vec<u8>,
    /// Base address of the VM stack (for validating pointer accesses).
    pub stack_base: u64,
    /// Base address of the context buffer.
    pub ctx_base: u64,
    /// Size of the context buffer.
    pub ctx_size: usize,
}

/// Dispatch a helper function call.
///
/// `regs` contains R1..R5 as arguments. Returns the value for R0.
pub fn call_helper(
    helper_id: u32,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    r5: u64,
    hctx: &mut HelperContext,
) -> u64 {
    match helper_id {
        BPF_FUNC_MAP_LOOKUP_ELEM => helper_map_lookup_elem(r1, r2, hctx),
        BPF_FUNC_MAP_UPDATE_ELEM => helper_map_update_elem(r1, r2, r3, r4, hctx),
        BPF_FUNC_MAP_DELETE_ELEM => helper_map_delete_elem(r1, r2, hctx),
        BPF_FUNC_KTIME_GET_NS => monotonic_time_nanos() as u64,
        BPF_FUNC_GET_CURRENT_PID_TGID => helper_get_current_pid_tgid(),
        BPF_FUNC_GET_CURRENT_UID_GID => helper_get_current_uid_gid(),
        BPF_FUNC_GET_CURRENT_COMM => helper_get_current_comm(r1, r2, hctx),
        BPF_FUNC_TRACE_PRINTK => helper_trace_printk(r1, r2, r3, r4, r5, hctx),
        BPF_FUNC_GET_PRANDOM_U32 => helper_get_prandom_u32(),
        BPF_FUNC_GET_SMP_PROCESSOR_ID => 0, // unikernel: always CPU 0
        _ => 0, // unknown helper returns 0 (verifier should have rejected)
    }
}

// ---------------------------------------------------------------------------
// Map helpers
// ---------------------------------------------------------------------------

fn helper_map_lookup_elem(map_idx: u64, key_ptr: u64, hctx: &mut HelperContext) -> u64 {
    let Some(map) = hctx.maps.get(map_idx as usize) else {
        return 0;
    };

    let key_size = map.key_size() as usize;
    let key = unsafe { core::slice::from_raw_parts(key_ptr as *const u8, key_size) };

    match map.lookup(key) {
        Some(value) => {
            // Store value in scratch buffer, return pointer to it.
            let offset = hctx.scratch.len();
            hctx.scratch.extend_from_slice(&value);
            hctx.scratch.as_ptr() as u64 + offset as u64
        }
        None => 0, // NULL
    }
}

fn helper_map_update_elem(
    map_idx: u64,
    key_ptr: u64,
    value_ptr: u64,
    flags: u64,
    hctx: &mut HelperContext,
) -> u64 {
    let Some(map) = hctx.maps.get(map_idx as usize) else {
        return u64::MAX; // -1 as error
    };

    let key_size = map.key_size() as usize;
    let value_size = map.value_size() as usize;

    let key = unsafe { core::slice::from_raw_parts(key_ptr as *const u8, key_size) };
    let value = unsafe { core::slice::from_raw_parts(value_ptr as *const u8, value_size) };

    match map.update(key, value, flags) {
        Ok(()) => 0,
        Err(_) => u64::MAX,
    }
}

fn helper_map_delete_elem(map_idx: u64, key_ptr: u64, hctx: &mut HelperContext) -> u64 {
    let Some(map) = hctx.maps.get(map_idx as usize) else {
        return u64::MAX;
    };

    let key_size = map.key_size() as usize;
    let key = unsafe { core::slice::from_raw_parts(key_ptr as *const u8, key_size) };

    match map.delete(key) {
        Ok(()) => 0,
        Err(_) => u64::MAX,
    }
}

// ---------------------------------------------------------------------------
// Process context helpers
// ---------------------------------------------------------------------------

fn helper_get_current_pid_tgid() -> u64 {
    let curr = current();
    if let Some(thr) = curr.try_as_thread() {
        let pid = thr.proc_data.proc.pid() as u64;
        let tid = curr.id().as_u64();
        (pid << 32) | (tid & 0xFFFF_FFFF)
    } else {
        0
    }
}

fn helper_get_current_uid_gid() -> u64 {
    // StarryOS runs as root (uid=0, gid=0)
    0
}

fn helper_get_current_comm(buf_ptr: u64, buf_size: u64, _hctx: &mut HelperContext) -> u64 {
    let curr = current();
    let name = curr.name();
    let name_bytes = name.as_bytes();

    let out_size = (buf_size as usize).min(16); // TASK_COMM_LEN = 16
    let copy_len = name_bytes.len().min(out_size.saturating_sub(1));

    let out = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, out_size) };
    out[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    // Null-terminate
    if copy_len < out_size {
        out[copy_len] = 0;
    }

    0 // success
}

// ---------------------------------------------------------------------------
// Debug helpers
// ---------------------------------------------------------------------------

fn helper_trace_printk(
    _fmt_ptr: u64,
    _fmt_size: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    _hctx: &mut HelperContext,
) -> u64 {
    // Simplified: just print the arguments since parsing format strings from
    // BPF memory is complex and error-prone.
    warn!(
        "bpf_trace_printk: arg1={arg1:#x}, arg2={arg2:#x}, arg3={arg3:#x}"
    );
    0
}

fn helper_get_prandom_u32() -> u64 {
    // Simple PRNG — use monotonic time as entropy source.
    // Not cryptographically secure, but sufficient for BPF use cases.
    let t = monotonic_time_nanos() as u64;
    // xorshift32-ish
    let mut x = t as u32;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x as u64
}
