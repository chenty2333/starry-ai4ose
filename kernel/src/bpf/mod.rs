//! eBPF subsystem: virtual machine, maps, verifier, and program management.

pub mod defs;
pub mod helpers;
pub mod map;
pub mod prog;
pub mod verifier;
pub mod vm;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;

use self::{map::BpfMap, prog::BpfProgram};

// ---------------------------------------------------------------------------
// Global BPF registry
// ---------------------------------------------------------------------------

static NEXT_MAP_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_PROG_ID: AtomicU32 = AtomicU32::new(1);

pub fn alloc_map_id() -> u32 {
    NEXT_MAP_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn alloc_prog_id() -> u32 {
    NEXT_PROG_ID.fetch_add(1, Ordering::Relaxed)
}

pub struct BpfRegistry {
    pub maps: BTreeMap<u32, Arc<dyn BpfMap>>,
    pub programs: BTreeMap<u32, Arc<BpfProgram>>,
}

impl BpfRegistry {
    const fn new() -> Self {
        Self {
            maps: BTreeMap::new(),
            programs: BTreeMap::new(),
        }
    }
}

pub static BPF_REGISTRY: Mutex<BpfRegistry> = Mutex::new(BpfRegistry::new());

/// Read bpf attr from user space. Reads `min(attr_size, size_of::<T>())` bytes,
/// zero-fills the rest. This provides forward/backward compatibility.
pub fn read_bpf_attr<T: bytemuck::AnyBitPattern>(
    attr_ptr: usize,
    attr_size: u32,
) -> axerrno::AxResult<T> {
    use alloc::vec;
    use axerrno::AxError;

    let want = core::mem::size_of::<T>();
    let copy_len = (attr_size as usize).min(want);
    if copy_len == 0 {
        return Err(AxError::InvalidInput);
    }

    let src = starry_vm::vm_load(attr_ptr as *const u8, copy_len)
        .map_err(|_| AxError::BadAddress)?;
    let mut buf = vec![0u8; want];
    buf[..copy_len].copy_from_slice(&src);
    Ok(bytemuck::pod_read_unaligned(&buf))
}
