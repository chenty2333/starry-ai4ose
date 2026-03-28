//! BPF program syscall command handlers.

use axerrno::{AxError, AxResult};

pub fn bpf_prog_load(_attr_ptr: usize, _attr_size: u32) -> AxResult<isize> {
    // Will be implemented in Step 7 (after verifier and VM).
    warn!("bpf_prog_load: not yet implemented");
    Err(AxError::Unsupported)
}

pub fn bpf_prog_test_run(_attr_ptr: usize, _attr_size: u32) -> AxResult<isize> {
    // Will be implemented in Step 7.
    warn!("bpf_prog_test_run: not yet implemented");
    Err(AxError::Unsupported)
}
