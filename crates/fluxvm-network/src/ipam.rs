// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Persistent /28 allocation for netns sandboxes inside 169.254.0.0/16.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const POOL_SIZE: u16 = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct IpamState {
    /// VM id (simple form) -> block index 0..4095.
    allocations: HashMap<String, u16>,
}

pub struct IpamStore {
    path: PathBuf,
    lock_path: PathBuf,
}

impl IpamStore {
    pub fn load(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("ipam.json"),
            lock_path: state_dir.join("ipam.lock"),
        }
    }

    /// Returns `(third_octet, fourth_octet_base)` for a /28 in 169.254.0.0/16.
    pub fn allocate(&self, id: Uuid) -> Result<(u8, u8)> {
        self.with_exclusive(|state| allocate_in(state, id))
    }

    /// Releases a VM's block; returns the former octets when one existed.
    pub fn release(&self, id: Uuid) -> Result<Option<(u8, u8)>> {
        self.with_exclusive(|state| {
            let key = id.simple().to_string();
            Ok(state.allocations.remove(&key).map(block_to_octets))
        })
    }

    pub fn lookup(&self, id: Uuid) -> Result<Option<(u8, u8)>> {
        self.with_shared(|state| {
            Ok(state
                .allocations
                .get(&id.simple().to_string())
                .copied()
                .map(block_to_octets))
        })
    }

    fn with_exclusive<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut IpamState) -> Result<T>,
    {
        let _guard = self.lock()?;
        let mut state = read_state(&self.path)?;
        let out = f(&mut state)?;
        write_state(&self.path, &state)?;
        Ok(out)
    }

    fn with_shared<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&IpamState) -> Result<T>,
    {
        let _guard = self.lock_shared()?;
        let state = read_state(&self.path)?;
        f(&state)
    }

    fn lock(&self) -> Result<LockGuard> {
        LockGuard::exclusive(&self.lock_path)
    }

    fn lock_shared(&self) -> Result<LockGuard> {
        LockGuard::shared(&self.lock_path)
    }
}

struct LockGuard {
    _file: fs::File,
}

impl LockGuard {
    fn exclusive(path: &Path) -> Result<Self> {
        let file = open_lock(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            bail!("locking ipam store: {}", std::io::Error::last_os_error());
        }
        Ok(Self { _file: file })
    }

    fn shared(path: &Path) -> Result<Self> {
        let file = open_lock(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
            bail!("locking ipam store: {}", std::io::Error::last_os_error());
        }
        Ok(Self { _file: file })
    }
}

fn open_lock(path: &Path) -> Result<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(path)
        .context("opening ipam lock file")
}

fn read_state(path: &Path) -> Result<IpamState> {
    if !path.exists() {
        return Ok(IpamState::default());
    }
    let raw = fs::read_to_string(path).context("reading ipam state")?;
    if raw.trim().is_empty() {
        return Ok(IpamState::default());
    }
    serde_json::from_str(&raw).context("parsing ipam state")
}

fn write_state(path: &Path, state: &IpamState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("creating ipam state dir")?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(state)?).context("writing ipam state")?;
    fs::rename(&tmp, path).context("renaming ipam state")?;
    Ok(())
}

fn allocate_in(state: &mut IpamState, id: Uuid) -> Result<(u8, u8)> {
    let key = id.simple().to_string();
    if let Some(block) = state.allocations.get(&key) {
        return Ok(block_to_octets(*block));
    }
    let used: HashSet<u16> = state.allocations.values().copied().collect();
    let block = (0..POOL_SIZE)
        .find(|n| !used.contains(n))
        .context("ipam pool exhausted (4096 /28 subnets in use)")?;
    state.allocations.insert(key, block);
    Ok(block_to_octets(block))
}

/// Maps block index to `(third_octet, fourth_octet_base)` for 169.254.{third}.{base}/28.
pub fn block_to_octets(block: u16) -> (u8, u8) {
    ((block / 16) as u8, ((block % 16) * 16) as u8)
}

/// Legacy UUID-hash fallback when no ipam record exists (pre-migration cleanup).
pub fn legacy_subnet_block(id: Uuid) -> (u8, u8) {
    block_to_octets((id.as_u128() % POOL_SIZE as u128) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_tests() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn allocate_and_release_round_trip() {
        let _guard = lock_tests();
        let dir = tempfile::tempdir().unwrap();
        let store = IpamStore::load(dir.path());
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let (t1, b1) = store.allocate(a).unwrap();
        assert_eq!(store.allocate(a).unwrap(), (t1, b1));
        let (t2, b2) = store.allocate(b).unwrap();
        assert!((t1, b1) != (t2, b2));

        assert_eq!(store.release(a).unwrap(), Some((t1, b1)));
        assert_eq!(store.release(a).unwrap(), None);

        let (t3, b3) = store.allocate(a).unwrap();
        assert!((t3, b3) != (t2, b2));
    }

    #[test]
    fn block_to_octets_covers_pool() {
        let (t, b) = block_to_octets(4095);
        assert_eq!(t, 255);
        assert_eq!(b, 240);
        let (t0, b0) = block_to_octets(0);
        assert_eq!((t0, b0), (0, 0));
    }
}
