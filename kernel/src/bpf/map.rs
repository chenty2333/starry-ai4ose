//! BPF map implementations (ArrayMap, HashMap).

use alloc::{sync::Arc, vec::Vec};

use axerrno::{AxError, AxResult};

use super::defs::*;

/// Trait for all BPF map types.
pub trait BpfMap: Send + Sync {
    fn map_type(&self) -> u32;
    fn key_size(&self) -> u32;
    fn value_size(&self) -> u32;
    fn max_entries(&self) -> u32;
    fn name(&self) -> [u8; BPF_OBJ_NAME_LEN];
    fn id(&self) -> u32;

    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> AxResult<()>;
    fn delete(&self, key: &[u8]) -> AxResult<()>;
    fn get_next_key(&self, key: Option<&[u8]>) -> Option<Vec<u8>>;
}

/// Create a map of the given type.
pub fn create_map(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    _flags: u32,
    name: [u8; BPF_OBJ_NAME_LEN],
    id: u32,
) -> AxResult<Arc<dyn BpfMap>> {
    match map_type {
        BPF_MAP_TYPE_ARRAY => Ok(Arc::new(ArrayMap::new(
            key_size,
            value_size,
            max_entries,
            name,
            id,
        )?)),
        BPF_MAP_TYPE_HASH => Ok(Arc::new(BpfHashMap::new(
            key_size,
            value_size,
            max_entries,
            name,
            id,
        )?)),
        _ => Err(AxError::InvalidInput),
    }
}

// ---------------------------------------------------------------------------
// ArrayMap
// ---------------------------------------------------------------------------

pub struct ArrayMap {
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    name: [u8; BPF_OBJ_NAME_LEN],
    id: u32,
    data: spin::Mutex<Vec<u8>>,
}

impl ArrayMap {
    fn new(
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        name: [u8; BPF_OBJ_NAME_LEN],
        id: u32,
    ) -> AxResult<Self> {
        if key_size != 4 || value_size == 0 || max_entries == 0 {
            return Err(AxError::InvalidInput);
        }
        let total = (max_entries as usize)
            .checked_mul(value_size as usize)
            .ok_or(AxError::NoMemory)?;
        Ok(Self {
            key_size,
            value_size,
            max_entries,
            name,
            id,
            data: spin::Mutex::new(alloc::vec![0u8; total]),
        })
    }

    fn index_range(&self, index: u32) -> Option<core::ops::Range<usize>> {
        if index >= self.max_entries {
            return None;
        }
        let start = index as usize * self.value_size as usize;
        let end = start + self.value_size as usize;
        Some(start..end)
    }

    fn key_to_index(key: &[u8]) -> Option<u32> {
        if key.len() != 4 {
            return None;
        }
        Some(u32::from_ne_bytes([key[0], key[1], key[2], key[3]]))
    }
}

impl BpfMap for ArrayMap {
    fn map_type(&self) -> u32 {
        BPF_MAP_TYPE_ARRAY
    }
    fn key_size(&self) -> u32 {
        self.key_size
    }
    fn value_size(&self) -> u32 {
        self.value_size
    }
    fn max_entries(&self) -> u32 {
        self.max_entries
    }
    fn name(&self) -> [u8; BPF_OBJ_NAME_LEN] {
        self.name
    }
    fn id(&self) -> u32 {
        self.id
    }

    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        let index = Self::key_to_index(key)?;
        let range = self.index_range(index)?;
        let data = self.data.lock();
        Some(data[range].to_vec())
    }

    fn update(&self, key: &[u8], value: &[u8], _flags: u64) -> AxResult<()> {
        let index = Self::key_to_index(key).ok_or(AxError::InvalidInput)?;
        let range = self.index_range(index).ok_or(AxError::InvalidInput)?;
        if value.len() != self.value_size as usize {
            return Err(AxError::InvalidInput);
        }
        let mut data = self.data.lock();
        data[range].copy_from_slice(value);
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> AxResult<()> {
        // Array maps: delete = zero the entry.
        let index = Self::key_to_index(key).ok_or(AxError::InvalidInput)?;
        let range = self.index_range(index).ok_or(AxError::InvalidInput)?;
        let mut data = self.data.lock();
        data[range].fill(0);
        Ok(())
    }

    fn get_next_key(&self, key: Option<&[u8]>) -> Option<Vec<u8>> {
        let next = match key {
            None => 0u32,
            Some(k) => Self::key_to_index(k)?.wrapping_add(1),
        };
        if next < self.max_entries {
            Some(next.to_ne_bytes().to_vec())
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// HashMap
// ---------------------------------------------------------------------------

pub struct BpfHashMap {
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    name: [u8; BPF_OBJ_NAME_LEN],
    id: u32,
    data: spin::Mutex<hashbrown::HashMap<Vec<u8>, Vec<u8>>>,
}

impl BpfHashMap {
    fn new(
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        name: [u8; BPF_OBJ_NAME_LEN],
        id: u32,
    ) -> AxResult<Self> {
        if key_size == 0 || value_size == 0 || max_entries == 0 {
            return Err(AxError::InvalidInput);
        }
        Ok(Self {
            key_size,
            value_size,
            max_entries,
            name,
            id,
            data: spin::Mutex::new(hashbrown::HashMap::new()),
        })
    }
}

impl BpfMap for BpfHashMap {
    fn map_type(&self) -> u32 {
        BPF_MAP_TYPE_HASH
    }
    fn key_size(&self) -> u32 {
        self.key_size
    }
    fn value_size(&self) -> u32 {
        self.value_size
    }
    fn max_entries(&self) -> u32 {
        self.max_entries
    }
    fn name(&self) -> [u8; BPF_OBJ_NAME_LEN] {
        self.name
    }
    fn id(&self) -> u32 {
        self.id
    }

    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.data.lock().get(key).cloned()
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> AxResult<()> {
        if key.len() != self.key_size as usize || value.len() != self.value_size as usize {
            return Err(AxError::InvalidInput);
        }
        let mut data = self.data.lock();
        let exists = data.contains_key(key);
        if flags == BPF_NOEXIST && exists {
            return Err(AxError::AlreadyExists);
        }
        if flags == BPF_EXIST && !exists {
            return Err(AxError::NotFound);
        }
        if !exists && data.len() >= self.max_entries as usize {
            return Err(AxError::StorageFull);
        }
        data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> AxResult<()> {
        let mut data = self.data.lock();
        if data.remove(key).is_some() {
            Ok(())
        } else {
            Err(AxError::NotFound)
        }
    }

    fn get_next_key(&self, key: Option<&[u8]>) -> Option<Vec<u8>> {
        let data = self.data.lock();
        match key {
            None => data.keys().next().cloned(),
            Some(k) => {
                let mut iter = data.keys();
                // Find the key, then return the next one.
                // Since HashMap iteration order is arbitrary, this just returns
                // "some other key" which is valid for BPF iteration semantics.
                let mut found = false;
                for entry_key in iter.by_ref() {
                    if entry_key.as_slice() == k {
                        found = true;
                        break;
                    }
                }
                if found {
                    iter.next().cloned()
                } else {
                    // Key not found: return the first key (Linux behavior).
                    data.keys().next().cloned()
                }
            }
        }
    }
}
