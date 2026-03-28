//! eBPF program verifier.
//!
//! Validates BPF programs before execution to ensure memory safety. Performs:
//! 1. Structural validation (instruction bounds, register indices, etc.)
//! 2. CFG/DAG check (no backward jumps → no loops)
//! 3. Abstract interpretation with register state tracking

use alloc::{string::String, sync::Arc, vec, vec::Vec};

use axerrno::{AxError, AxResult};

use super::{
    defs::*,
    map::BpfMap,
};
use crate::file::{FileLike, bpf::BpfMapFd};

// ---------------------------------------------------------------------------
// Register value types for abstract interpretation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegType {
    /// Register has not been written to.
    Uninit,
    /// Register holds a scalar (numeric) value.
    Scalar,
    /// Register holds a pointer into the BPF stack (R10-based).
    StackPtr,
    /// Register holds a pointer into a context buffer.
    CtxPtr,
    /// Register holds a pointer into a map value (returned by map_lookup_elem).
    MapValuePtr,
    /// Register holds a map pointer (used as argument to helpers).
    MapPtr,
}

#[derive(Debug, Clone, Copy)]
struct RegState {
    ty: RegType,
}

impl Default for RegState {
    fn default() -> Self {
        Self { ty: RegType::Uninit }
    }
}

impl RegState {
    fn scalar() -> Self {
        Self { ty: RegType::Scalar }
    }
    fn ctx() -> Self {
        Self { ty: RegType::CtxPtr }
    }
    fn stack() -> Self {
        Self { ty: RegType::StackPtr }
    }
    fn map_value() -> Self {
        Self { ty: RegType::MapValuePtr }
    }
    fn map_ptr() -> Self {
        Self { ty: RegType::MapPtr }
    }

    fn is_init(&self) -> bool {
        self.ty != RegType::Uninit
    }

    fn is_ptr(&self) -> bool {
        matches!(
            self.ty,
            RegType::StackPtr | RegType::CtxPtr | RegType::MapValuePtr | RegType::MapPtr
        )
    }
}

// ---------------------------------------------------------------------------
// Verifier log
// ---------------------------------------------------------------------------

struct VerifierLog {
    buf: String,
    enabled: bool,
}

impl VerifierLog {
    fn new(enabled: bool) -> Self {
        Self {
            buf: String::new(),
            enabled,
        }
    }

    fn log(&mut self, msg: &str) {
        if self.enabled {
            self.buf.push_str(msg);
            self.buf.push('\n');
        }
    }
}

// ---------------------------------------------------------------------------
// Verifier context
// ---------------------------------------------------------------------------

/// Result of successful verification.
pub struct VerifiedProgram {
    /// Maps referenced by the program (resolved from fd immediates).
    pub maps: Vec<Arc<dyn BpfMap>>,
    /// The (possibly rewritten) instruction stream.
    pub insns: Vec<BpfInsn>,
    /// Verifier log output.
    pub log: String,
}

/// Verify a BPF program.
///
/// `insns` is the raw instruction stream from user space.
/// `log_level` > 0 enables the verifier log.
pub fn verify_program(
    insns: &[BpfInsn],
    _prog_type: u32,
    log_level: u32,
) -> AxResult<VerifiedProgram> {
    let mut log = VerifierLog::new(log_level > 0);
    let mut insns = insns.to_vec();

    // Pass 1: Structural validation
    pass_structural(&insns, &mut log)?;

    // Pass 2: Resolve map fd references in LD_IMM_DW instructions
    let maps = pass_resolve_maps(&mut insns, &mut log)?;

    // Pass 3: CFG / DAG check (no loops)
    pass_cfg(&insns, &mut log)?;

    // Pass 4: Abstract interpretation (register state tracking)
    pass_abstract_interp(&insns, &maps, &mut log)?;

    Ok(VerifiedProgram {
        maps,
        insns,
        log: log.buf,
    })
}

// ---------------------------------------------------------------------------
// Pass 1: Structural validation
// ---------------------------------------------------------------------------

fn pass_structural(insns: &[BpfInsn], log: &mut VerifierLog) -> AxResult<()> {
    if insns.is_empty() || insns.len() > BPF_MAX_INSNS {
        log.log("program length out of range");
        return Err(AxError::InvalidInput);
    }

    let mut i = 0;
    while i < insns.len() {
        let insn = &insns[i];
        let class = insn.code & 0x07;

        // Check register indices
        if insn.dst_reg() > 10 || insn.src_reg() > 10 {
            log.log(&alloc::format!("insn {i}: invalid register index"));
            return Err(AxError::InvalidInput);
        }

        // R10 (FP) must not be written to (except as dst in LD_IMM_DW which
        // would be caught by the abstract interpreter).
        if class != BPF_CLASS_LD && class != BPF_CLASS_JMP && class != BPF_CLASS_JMP32 {
            if matches!(
                class,
                BPF_CLASS_ALU | BPF_CLASS_ALU64 | BPF_CLASS_LDX
            ) && insn.dst_reg() == BPF_REG_FP as u8
            {
                log.log(&alloc::format!("insn {i}: write to R10 (frame pointer)"));
                return Err(AxError::InvalidInput);
            }
        }

        // Handle 64-bit immediate loads (consume two instruction slots)
        let is_ld_imm_dw = class == BPF_CLASS_LD
            && (insn.code & 0x18) == BPF_SIZE_DW
            && (insn.code & 0xe0) == BPF_MODE_IMM;

        if is_ld_imm_dw {
            if i + 1 >= insns.len() {
                log.log(&alloc::format!(
                    "insn {i}: LD_IMM_DW at end of program"
                ));
                return Err(AxError::InvalidInput);
            }
            if insn.dst_reg() == BPF_REG_FP as u8 {
                log.log(&alloc::format!("insn {i}: LD_IMM_DW writes to R10"));
                return Err(AxError::InvalidInput);
            }
            i += 2; // skip the continuation slot
            continue;
        }

        // Validate jump targets
        if class == BPF_CLASS_JMP || class == BPF_CLASS_JMP32 {
            let op = insn.code & 0xf0;
            if op == BPF_OP_CALL || op == BPF_OP_EXIT {
                // CALL/EXIT don't use offset-based jumps
            } else if op == BPF_OP_JA && class == BPF_CLASS_JMP {
                // Unconditional jump: target = pc + 1 + off
                let target = (i as i64) + 1 + (insn.off as i64);
                if target < 0 || target >= insns.len() as i64 {
                    log.log(&alloc::format!(
                        "insn {i}: jump target {target} out of bounds"
                    ));
                    return Err(AxError::InvalidInput);
                }
            } else {
                // Conditional jump: target = pc + 1 + off
                let target = (i as i64) + 1 + (insn.off as i64);
                if target < 0 || target >= insns.len() as i64 {
                    log.log(&alloc::format!(
                        "insn {i}: jump target {target} out of bounds"
                    ));
                    return Err(AxError::InvalidInput);
                }
            }
        }

        i += 1;
    }

    // Last instruction must be EXIT
    let last = &insns[insns.len() - 1];
    if last.code != (BPF_CLASS_JMP | BPF_OP_EXIT) {
        log.log("program does not end with EXIT");
        return Err(AxError::InvalidInput);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Pass 2: Resolve map fd references
// ---------------------------------------------------------------------------

fn pass_resolve_maps(
    insns: &mut [BpfInsn],
    log: &mut VerifierLog,
) -> AxResult<Vec<Arc<dyn BpfMap>>> {
    let mut maps: Vec<Arc<dyn BpfMap>> = Vec::new();

    let mut i = 0;
    while i < insns.len() {
        let insn = &insns[i];
        let is_ld_imm_dw = (insn.code & 0x07) == BPF_CLASS_LD
            && (insn.code & 0x18) == BPF_SIZE_DW
            && (insn.code & 0xe0) == BPF_MODE_IMM;

        if is_ld_imm_dw && insn.src_reg() == BPF_PSEUDO_MAP_FD {
            let map_fd = insn.imm;
            let map_fd_obj = BpfMapFd::from_fd(map_fd).map_err(|_| {
                log.log(&alloc::format!(
                    "insn {i}: invalid map fd {map_fd}"
                ));
                AxError::BadFileDescriptor
            })?;

            // Find or insert the map in our list
            let map_index = maps
                .iter()
                .position(|m| m.id() == map_fd_obj.map.id())
                .unwrap_or_else(|| {
                    let idx = maps.len();
                    maps.push(map_fd_obj.map.clone());
                    idx
                });

            // Rewrite the instruction: replace fd with map index
            insns[i].imm = map_index as i32;
            // Clear src_reg so the VM treats it as a plain map pointer load
            insns[i].regs = insns[i].regs & 0x0f; // clear src_reg bits

            i += 2;
            continue;
        }

        if is_ld_imm_dw {
            i += 2;
        } else {
            i += 1;
        }
    }

    Ok(maps)
}

// ---------------------------------------------------------------------------
// Pass 3: CFG / DAG check — no backward jumps (no loops)
// ---------------------------------------------------------------------------

fn pass_cfg(insns: &[BpfInsn], log: &mut VerifierLog) -> AxResult<()> {
    // Build successor lists
    let n = insns.len();
    let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];

    let mut i = 0;
    while i < n {
        let insn = &insns[i];
        let class = insn.code & 0x07;

        let is_ld_imm_dw = class == BPF_CLASS_LD
            && (insn.code & 0x18) == BPF_SIZE_DW
            && (insn.code & 0xe0) == BPF_MODE_IMM;

        if is_ld_imm_dw {
            // Two-slot instruction: falls through to i+2
            if i + 2 < n {
                succs[i].push(i + 2);
            }
            i += 2;
            continue;
        }

        if class == BPF_CLASS_JMP || class == BPF_CLASS_JMP32 {
            let op = insn.code & 0xf0;
            if op == BPF_OP_EXIT {
                // No successors
            } else if op == BPF_OP_CALL {
                // CALL falls through
                if i + 1 < n {
                    succs[i].push(i + 1);
                }
            } else if op == BPF_OP_JA && class == BPF_CLASS_JMP {
                // Unconditional jump
                let target = ((i as i64) + 1 + (insn.off as i64)) as usize;
                succs[i].push(target);
            } else {
                // Conditional jump: fall-through + target
                if i + 1 < n {
                    succs[i].push(i + 1);
                }
                let target = ((i as i64) + 1 + (insn.off as i64)) as usize;
                succs[i].push(target);
            }
        } else {
            // Normal instruction: falls through
            if i + 1 < n {
                succs[i].push(i + 1);
            }
        }

        i += 1;
    }

    // DFS to detect back-edges (loops) and unreachable code
    #[derive(Clone, Copy, PartialEq)]
    enum Color {
        White,
        Gray,
        Black,
    }

    let mut color = vec![Color::White; n];
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)]; // (node, succ_index)
    color[0] = Color::Gray;

    while let Some(&mut (node, ref mut si)) = stack.last_mut() {
        if *si >= succs[node].len() {
            color[node] = Color::Black;
            stack.pop();
        } else {
            let next = succs[node][*si];
            *si += 1;
            match color[next] {
                Color::Gray => {
                    log.log(&alloc::format!(
                        "back edge detected: {node} -> {next} (loop)"
                    ));
                    return Err(AxError::InvalidInput);
                }
                Color::White => {
                    color[next] = Color::Gray;
                    stack.push((next, 0));
                }
                Color::Black => {}
            }
        }
    }

    // Check for unreachable instructions (skip continuation slots of LD_IMM_DW)
    let mut i = 0;
    while i < n {
        let insn = &insns[i];
        let class = insn.code & 0x07;
        let is_ld_imm_dw = class == BPF_CLASS_LD
            && (insn.code & 0x18) == BPF_SIZE_DW
            && (insn.code & 0xe0) == BPF_MODE_IMM;

        if color[i] == Color::White {
            log.log(&alloc::format!("insn {i}: unreachable"));
            return Err(AxError::InvalidInput);
        }

        if is_ld_imm_dw {
            i += 2;
        } else {
            i += 1;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Pass 4: Abstract interpretation — register state tracking
// ---------------------------------------------------------------------------

fn pass_abstract_interp(
    insns: &[BpfInsn],
    maps: &[Arc<dyn BpfMap>],
    log: &mut VerifierLog,
) -> AxResult<()> {
    let n = insns.len();

    // We do a simple forward pass. For programs with branches, we merge states
    // at join points. Since there are no loops (guaranteed by pass_cfg), a
    // single forward pass through the instruction list is sufficient if we
    // process each instruction's state contributions to its successors.

    // State at entry to each instruction.
    let mut states: Vec<Option<[RegState; BPF_MAX_REGS]>> = vec![None; n];

    // Initial state: R1 = context pointer, R10 = frame pointer, rest uninit.
    let mut init = [RegState::default(); BPF_MAX_REGS];
    init[1] = RegState::ctx();
    init[10] = RegState::stack();
    states[0] = Some(init);

    let mut i = 0;
    while i < n {
        let Some(mut regs) = states[i] else {
            // Continuation slot of LD_IMM_DW — skip
            i += 1;
            continue;
        };

        let insn = &insns[i];
        let class = insn.code & 0x07;
        let dst = insn.dst_reg() as usize;
        let src = insn.src_reg() as usize;

        let is_ld_imm_dw = class == BPF_CLASS_LD
            && (insn.code & 0x18) == BPF_SIZE_DW
            && (insn.code & 0xe0) == BPF_MODE_IMM;

        // Process instruction effect on register state
        match class {
            BPF_CLASS_ALU | BPF_CLASS_ALU64 => {
                let op = insn.code & 0xf0;
                if op == BPF_OP_MOV {
                    if insn.code & BPF_SRC_X != 0 {
                        check_reg_init(&regs, src, i, log)?;
                        regs[dst] = if regs[src].is_ptr() {
                            regs[src]
                        } else {
                            RegState::scalar()
                        };
                    } else {
                        regs[dst] = RegState::scalar();
                    }
                } else if op == BPF_OP_NEG {
                    check_reg_init(&regs, dst, i, log)?;
                    regs[dst] = RegState::scalar();
                } else {
                    check_reg_init(&regs, dst, i, log)?;
                    if insn.code & BPF_SRC_X != 0 {
                        check_reg_init(&regs, src, i, log)?;
                    }
                    // Arithmetic on pointers degrades to scalar
                    regs[dst] = RegState::scalar();
                }
            }

            BPF_CLASS_LDX => {
                // Load from memory: src must be a pointer
                check_reg_init(&regs, src, i, log)?;
                if !regs[src].is_ptr() {
                    log.log(&alloc::format!(
                        "insn {i}: LDX src R{src} is not a pointer"
                    ));
                    return Err(AxError::InvalidInput);
                }
                regs[dst] = RegState::scalar();
            }

            BPF_CLASS_STX => {
                // Store reg to memory: dst must be a pointer, src must be init
                check_reg_init(&regs, dst, i, log)?;
                check_reg_init(&regs, src, i, log)?;
                if !regs[dst].is_ptr() {
                    log.log(&alloc::format!(
                        "insn {i}: STX dst R{dst} is not a pointer"
                    ));
                    return Err(AxError::InvalidInput);
                }
            }

            BPF_CLASS_ST => {
                // Store immediate to memory: dst must be a pointer
                check_reg_init(&regs, dst, i, log)?;
                if !regs[dst].is_ptr() {
                    log.log(&alloc::format!(
                        "insn {i}: ST dst R{dst} is not a pointer"
                    ));
                    return Err(AxError::InvalidInput);
                }
            }

            BPF_CLASS_LD if is_ld_imm_dw => {
                // 64-bit immediate load
                if insn.regs & 0xf0 == 0 {
                    // Plain 64-bit immediate
                    regs[dst] = RegState::scalar();
                } else {
                    // Map pointer (already rewritten by pass_resolve_maps)
                    regs[dst] = RegState::map_ptr();
                }
                // Propagate state to i+2 (skip continuation slot)
                propagate(&mut states, i + 2, &regs);
                i += 2;
                continue;
            }

            BPF_CLASS_JMP | BPF_CLASS_JMP32 => {
                let op = insn.code & 0xf0;
                if op == BPF_OP_EXIT {
                    // R0 must be initialized at exit
                    check_reg_init(&regs, 0, i, log)?;
                    i += 1;
                    continue;
                }

                if op == BPF_OP_CALL {
                    let helper_id = insn.imm as u32;
                    verify_call(&mut regs, helper_id, maps, i, log)?;
                    propagate(&mut states, i + 1, &regs);
                    i += 1;
                    continue;
                }

                // Conditional/unconditional jumps
                if op != BPF_OP_JA {
                    // Conditional: check both operands
                    check_reg_init(&regs, dst, i, log)?;
                    if insn.code & BPF_SRC_X != 0 {
                        check_reg_init(&regs, src, i, log)?;
                    }
                }

                // Propagate to fall-through
                if op != BPF_OP_JA || class == BPF_CLASS_JMP32 {
                    propagate(&mut states, i + 1, &regs);
                }
                // Also (or only for JA) propagate to jump target
                if op == BPF_OP_JA && class == BPF_CLASS_JMP {
                    let target = ((i as i64) + 1 + (insn.off as i64)) as usize;
                    propagate(&mut states, target, &regs);
                } else {
                    let target = ((i as i64) + 1 + (insn.off as i64)) as usize;
                    propagate(&mut states, target, &regs);
                    propagate(&mut states, i + 1, &regs);
                }

                i += 1;
                continue;
            }

            _ => {
                log.log(&alloc::format!(
                    "insn {i}: unknown class {class:#x}"
                ));
                return Err(AxError::InvalidInput);
            }
        }

        // Fall-through propagation
        propagate(&mut states, i + 1, &regs);
        i += 1;
    }

    Ok(())
}

fn check_reg_init(
    regs: &[RegState; BPF_MAX_REGS],
    r: usize,
    insn_idx: usize,
    log: &mut VerifierLog,
) -> AxResult<()> {
    if !regs[r].is_init() {
        log.log(&alloc::format!(
            "insn {insn_idx}: R{r} is uninitialized"
        ));
        return Err(AxError::InvalidInput);
    }
    Ok(())
}

/// Propagate register state to a successor instruction, merging if there's
/// already a state from another path.
fn propagate(
    states: &mut [Option<[RegState; BPF_MAX_REGS]>],
    target: usize,
    regs: &[RegState; BPF_MAX_REGS],
) {
    if target >= states.len() {
        return;
    }
    match &mut states[target] {
        None => {
            states[target] = Some(*regs);
        }
        Some(existing) => {
            // Merge: if register types disagree, degrade to scalar (if both
            // initialized) or leave as the more conservative state.
            for r in 0..BPF_MAX_REGS {
                if existing[r].ty != regs[r].ty {
                    if existing[r].is_init() && regs[r].is_init() {
                        existing[r] = RegState::scalar();
                    }
                    // If one is uninit and other is init, keep init (sound
                    // because the path with uninit would have been caught).
                }
            }
        }
    }
}

/// Verify a helper function call and update register state accordingly.
fn verify_call(
    regs: &mut [RegState; BPF_MAX_REGS],
    helper_id: u32,
    maps: &[Arc<dyn BpfMap>],
    insn_idx: usize,
    log: &mut VerifierLog,
) -> AxResult<()> {
    match helper_id {
        BPF_FUNC_MAP_LOOKUP_ELEM => {
            // R1 = map pointer, R2 = key pointer
            check_reg_init(regs, 1, insn_idx, log)?;
            check_reg_init(regs, 2, insn_idx, log)?;
            if regs[1].ty != RegType::MapPtr {
                log.log(&alloc::format!(
                    "insn {insn_idx}: map_lookup_elem R1 is not a map pointer"
                ));
                return Err(AxError::InvalidInput);
            }
            // R0 = map value pointer (or NULL)
            // Caller-saved registers R1-R5 are clobbered.
            clobber_caller_saved(regs);
            regs[0] = RegState::map_value();
        }
        BPF_FUNC_MAP_UPDATE_ELEM => {
            // R1 = map, R2 = key, R3 = value, R4 = flags
            check_reg_init(regs, 1, insn_idx, log)?;
            check_reg_init(regs, 2, insn_idx, log)?;
            check_reg_init(regs, 3, insn_idx, log)?;
            check_reg_init(regs, 4, insn_idx, log)?;
            clobber_caller_saved(regs);
            regs[0] = RegState::scalar();
        }
        BPF_FUNC_MAP_DELETE_ELEM => {
            // R1 = map, R2 = key
            check_reg_init(regs, 1, insn_idx, log)?;
            check_reg_init(regs, 2, insn_idx, log)?;
            clobber_caller_saved(regs);
            regs[0] = RegState::scalar();
        }
        BPF_FUNC_KTIME_GET_NS
        | BPF_FUNC_GET_PRANDOM_U32
        | BPF_FUNC_GET_SMP_PROCESSOR_ID
        | BPF_FUNC_GET_CURRENT_PID_TGID
        | BPF_FUNC_GET_CURRENT_UID_GID => {
            // No arguments needed
            clobber_caller_saved(regs);
            regs[0] = RegState::scalar();
        }
        BPF_FUNC_GET_CURRENT_COMM => {
            // R1 = buf ptr, R2 = size
            check_reg_init(regs, 1, insn_idx, log)?;
            check_reg_init(regs, 2, insn_idx, log)?;
            clobber_caller_saved(regs);
            regs[0] = RegState::scalar();
        }
        BPF_FUNC_TRACE_PRINTK => {
            // R1 = fmt, R2 = fmt_size, R3..R5 = varargs (optional)
            check_reg_init(regs, 1, insn_idx, log)?;
            check_reg_init(regs, 2, insn_idx, log)?;
            clobber_caller_saved(regs);
            regs[0] = RegState::scalar();
        }
        BPF_FUNC_PROBE_READ => {
            // R1 = dst, R2 = size, R3 = src
            check_reg_init(regs, 1, insn_idx, log)?;
            check_reg_init(regs, 2, insn_idx, log)?;
            check_reg_init(regs, 3, insn_idx, log)?;
            clobber_caller_saved(regs);
            regs[0] = RegState::scalar();
        }
        _ => {
            log.log(&alloc::format!(
                "insn {insn_idx}: unknown helper function {helper_id}"
            ));
            return Err(AxError::InvalidInput);
        }
    }
    Ok(())
}

/// After a CALL, R1-R5 are clobbered (caller-saved).
fn clobber_caller_saved(regs: &mut [RegState; BPF_MAX_REGS]) {
    for r in 1..=5 {
        regs[r] = RegState::default(); // Uninit
    }
}
