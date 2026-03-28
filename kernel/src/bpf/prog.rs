//! BPF program storage and metadata.

use alloc::{sync::Arc, vec::Vec};

use super::{defs::*, map::BpfMap};

/// A loaded (and verified) BPF program.
pub struct BpfProgram {
    pub prog_type: u32,
    pub insns: Vec<BpfInsn>,
    pub name: [u8; BPF_OBJ_NAME_LEN],
    pub prog_id: u32,
    pub expected_attach_type: u32,
    /// Maps referenced by this program (resolved during verification).
    pub maps: Vec<Arc<dyn BpfMap>>,
    /// GPL-compatible license.
    pub gpl_compatible: bool,
}
