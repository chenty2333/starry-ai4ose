//! BPF map syscall command handlers.

use axerrno::{AxError, AxResult};

use crate::{
    bpf::{
        BPF_REGISTRY, alloc_map_id,
        defs::*,
        map::{self, BpfMap},
        read_bpf_attr,
    },
    file::FileLike,
};

pub fn bpf_map_create(attr_ptr: usize, attr_size: u32) -> AxResult<isize> {
    let attr: BpfAttrMapCreate = read_bpf_attr(attr_ptr, attr_size)?;
    debug!(
        "bpf_map_create: type={}, key_size={}, value_size={}, max_entries={}",
        attr.map_type, attr.key_size, attr.value_size, attr.max_entries
    );

    let id = alloc_map_id();
    let map = map::create_map(
        attr.map_type,
        attr.key_size,
        attr.value_size,
        attr.max_entries,
        attr.map_flags,
        attr.map_name,
        id,
    )?;

    // Register in global registry.
    BPF_REGISTRY.lock().maps.insert(id, map.clone());

    // Create fd for the map.
    use crate::file::bpf::BpfMapFd;
    BpfMapFd::new(map, id, attr.map_name)
        .add_to_fd_table(false)
        .map(|fd| fd as isize)
}

pub fn bpf_map_lookup_elem(attr_ptr: usize, attr_size: u32) -> AxResult<isize> {
    let attr: BpfAttrMapElem = read_bpf_attr(attr_ptr, attr_size)?;

    let map_fd = crate::file::bpf::BpfMapFd::from_fd(attr.map_fd as _)?;
    let map = &map_fd.map;

    let key_size = map.key_size() as usize;
    let value_size = map.value_size() as usize;

    let key = starry_vm::vm_load(attr.key as *const u8, key_size)?;
    let value = map.lookup(&key).ok_or(AxError::NotFound)?;

    starry_vm::vm_write_slice(attr.value_or_next_key as *mut u8, &value[..value_size])?;
    Ok(0)
}

pub fn bpf_map_update_elem(attr_ptr: usize, attr_size: u32) -> AxResult<isize> {
    let attr: BpfAttrMapElem = read_bpf_attr(attr_ptr, attr_size)?;

    let map_fd = crate::file::bpf::BpfMapFd::from_fd(attr.map_fd as _)?;
    let map = &map_fd.map;

    let key_size = map.key_size() as usize;
    let value_size = map.value_size() as usize;

    let key = starry_vm::vm_load(attr.key as *const u8, key_size)?;
    let value = starry_vm::vm_load(attr.value_or_next_key as *const u8, value_size)?;

    map.update(&key, &value, attr.flags)?;
    Ok(0)
}

pub fn bpf_map_delete_elem(attr_ptr: usize, attr_size: u32) -> AxResult<isize> {
    let attr: BpfAttrMapElem = read_bpf_attr(attr_ptr, attr_size)?;

    let map_fd = crate::file::bpf::BpfMapFd::from_fd(attr.map_fd as _)?;
    let map = &map_fd.map;

    let key = starry_vm::vm_load(attr.key as *const u8, map.key_size() as usize)?;
    map.delete(&key)?;
    Ok(0)
}

pub fn bpf_map_get_next_key(attr_ptr: usize, attr_size: u32) -> AxResult<isize> {
    let attr: BpfAttrMapElem = read_bpf_attr(attr_ptr, attr_size)?;

    let map_fd = crate::file::bpf::BpfMapFd::from_fd(attr.map_fd as _)?;
    let map = &map_fd.map;

    let key = if attr.key == 0 {
        None
    } else {
        Some(starry_vm::vm_load(
            attr.key as *const u8,
            map.key_size() as usize,
        )?)
    };

    let next = map
        .get_next_key(key.as_deref())
        .ok_or(AxError::NotFound)?;

    starry_vm::vm_write_slice(attr.value_or_next_key as *mut u8, &next)?;
    Ok(0)
}
