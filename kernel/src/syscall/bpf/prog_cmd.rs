//! BPF program syscall command handlers: PROG_LOAD and PROG_TEST_RUN.

use alloc::{sync::Arc, vec::Vec};
use core::mem::{offset_of, size_of};

use axerrno::{AxError, AxResult};

use crate::{
    bpf::{
        alloc_prog_id,
        defs::*,
        prog::{BpfProgram, uses_raw_ctx_prog_type},
        read_bpf_attr, require_bpf_attr_range, verifier,
        vm::BpfVm,
        write_bpf_attr_value,
    },
    file::{FileLike, bpf::BpfProgFd},
};

pub fn bpf_prog_load(attr_ptr: usize, attr_size: u32) -> AxResult<isize> {
    let attr: BpfAttrProgLoad = read_bpf_attr(attr_ptr, attr_size)?;
    debug!(
        "bpf_prog_load: type={}, insn_cnt={}, log_level={}",
        attr.prog_type, attr.insn_cnt, attr.log_level
    );

    validate_prog_load_attr(&attr)?;

    // Validate basic parameters
    if attr.insn_cnt == 0 || attr.insn_cnt > BPF_MAX_INSNS as u32 {
        return Err(AxError::InvalidInput);
    }

    // Read instructions from user space
    let insns = starry_vm::vm_load(attr.insns as *const BpfInsn, attr.insn_cnt as usize)
        .map_err(|_| AxError::BadAddress)?;

    // Read license string (for GPL check)
    let license = if attr.license != 0 {
        starry_vm::vm_load_until_nul(attr.license as *const u8).unwrap_or_default()
    } else {
        alloc::vec::Vec::new()
    };
    let gpl_compatible = license_is_gpl(&license);

    // Run the verifier
    let verified = verifier::verify_program(&insns, attr.prog_type, attr.log_level)?;

    // Write verifier log to user buffer if requested
    if attr.log_level > 0 && attr.log_buf != 0 && attr.log_size > 0 {
        let log_bytes = verified.log.as_bytes();
        let copy_len = log_bytes.len().min(attr.log_size as usize - 1);
        if copy_len > 0 {
            let _ = starry_vm::vm_write_slice(attr.log_buf as *mut u8, &log_bytes[..copy_len]);
            // Null-terminate
            let _ =
                starry_vm::vm_write_slice((attr.log_buf as usize + copy_len) as *mut u8, &[0u8]);
        }
    }

    // Create program object
    let prog_id = alloc_prog_id();
    let program = Arc::new(BpfProgram {
        prog_type: attr.prog_type,
        insns: verified.insns,
        decoded_insns: verified.decoded_insns,
        name: attr.prog_name,
        prog_id,
        expected_attach_type: attr.expected_attach_type,
        maps: verified.maps,
        gpl_compatible,
    });

    // Create fd
    BpfProgFd::new(program)
        .add_to_fd_table(false)
        .map(|fd| fd as isize)
}

pub fn bpf_prog_test_run(attr_ptr: usize, attr_size: u32) -> AxResult<isize> {
    require_bpf_attr_range::<BpfAttrTestRun>(attr_size, size_of::<BpfAttrTestRun>())?;
    let attr: BpfAttrTestRun = read_bpf_attr(attr_ptr, attr_size)?;
    debug!(
        "bpf_prog_test_run: prog_fd={}, data_in={}, ctx_in={}, repeat={}",
        attr.prog_fd, attr.data_size_in, attr.ctx_size_in, attr.repeat
    );

    // Get the program from fd
    let prog_fd = BpfProgFd::from_fd(attr.prog_fd as _)?;
    let prog = &prog_fd.prog;

    validate_prog_test_run_attr(&attr, prog.prog_type)?;

    // Read context from user space (if provided)
    let ctx_size = attr.ctx_size_in as usize;
    let mut ctx = if ctx_size > 0 && attr.ctx_in != 0 {
        starry_vm::vm_load(attr.ctx_in as *const u8, ctx_size).map_err(|_| AxError::BadAddress)?
    } else {
        Vec::new()
    };

    // Run the program
    let repeat = if attr.repeat == 0 { 1 } else { attr.repeat };
    let mut retval = 0u64;
    let start = axhal::time::monotonic_time_nanos();

    for _ in 0..repeat {
        let mut vm = BpfVm::new(&prog.insns, &prog.decoded_insns, &prog.maps);
        retval = vm.execute(&mut ctx)?;
    }

    let duration = (axhal::time::monotonic_time_nanos() - start) as u32;

    write_bpf_attr_value::<BpfAttrTestRun, _>(
        attr_ptr,
        attr_size,
        offset_of!(BpfAttrTestRun, retval),
        &(retval as u32),
    )?;
    write_bpf_attr_value::<BpfAttrTestRun, _>(
        attr_ptr,
        attr_size,
        offset_of!(BpfAttrTestRun, duration),
        &duration,
    )?;

    write_bpf_attr_value::<BpfAttrTestRun, _>(
        attr_ptr,
        attr_size,
        offset_of!(BpfAttrTestRun, ctx_size_out),
        &0u32,
    )?;

    write_bpf_attr_value::<BpfAttrTestRun, _>(
        attr_ptr,
        attr_size,
        offset_of!(BpfAttrTestRun, data_size_out),
        &0u32,
    )?;

    Ok(0)
}

fn validate_prog_load_attr(attr: &BpfAttrProgLoad) -> AxResult<()> {
    if !uses_raw_ctx_prog_type(attr.prog_type) {
        return Err(AxError::InvalidInput);
    }

    if attr.prog_flags != 0
        || attr.expected_attach_type != 0
        || attr.prog_ifindex != 0
        || attr.prog_btf_fd != 0
        || attr.func_info_rec_size != 0
        || attr.func_info != 0
        || attr.func_info_cnt != 0
        || attr.line_info_rec_size != 0
        || attr.line_info != 0
        || attr.line_info_cnt != 0
        || attr.attach_btf_id != 0
        || attr.attach_prog_fd_or_btf_obj_fd != 0
        || attr.core_relo_cnt != 0
        || attr.fd_array != 0
        || attr.core_relos != 0
        || attr.core_relo_rec_size != 0
    {
        return Err(AxError::InvalidInput);
    }

    Ok(())
}

fn validate_prog_test_run_attr(attr: &BpfAttrTestRun, prog_type: u32) -> AxResult<()> {
    if !uses_raw_ctx_prog_type(prog_type) {
        return Err(AxError::InvalidInput);
    }

    if attr.flags != 0 || attr.cpu != 0 || attr.batch_size != 0 {
        return Err(AxError::InvalidInput);
    }

    if attr.data_size_in != 0 || attr.data_size_out != 0 || attr.data_in != 0 || attr.data_out != 0
    {
        return Err(AxError::InvalidInput);
    }

    if attr.ctx_size_in > 0 && attr.ctx_in == 0 {
        return Err(AxError::InvalidInput);
    }
    if attr.ctx_out != 0 || attr.ctx_size_out != 0 {
        return Err(AxError::InvalidInput);
    }

    Ok(())
}

fn license_is_gpl(license: &[u8]) -> bool {
    let s = core::str::from_utf8(license).unwrap_or("");
    s.starts_with("GPL") || s.starts_with("Dual MIT/GPL") || s.starts_with("Dual BSD/GPL")
}
