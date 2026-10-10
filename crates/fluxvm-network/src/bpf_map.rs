// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Native writes to an already-pinned hash map. Open once for a restore,
//! avoiding a bpftool subprocess and a pathname lookup for every entry.
//! Map metadata is checked before passing any key/value pointers to the kernel.

use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub(crate) struct MapLayout {
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

impl MapLayout {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn validate(self, key: &[u8], value: &[u8]) -> io::Result<()> {
        if key.len() != self.key_size as usize || value.len() != self.value_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "BPF map key/value size mismatch",
            ));
        }
        Ok(())
    }

    pub fn check_capacity(self, entries: usize) -> io::Result<()> {
        if entries > self.max_entries as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "conntrack snapshot exceeds BPF map capacity",
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    const BPF_MAP_UPDATE_ELEM: u32 = 2;
    const BPF_OBJ_GET: u32 = 7;
    const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;

    #[repr(C)]
    #[derive(Default)]
    struct ObjectAttr {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct InfoAttr {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }
    // Only request the stable prefix of bpf_map_info, available since Linux 4.13.
    #[repr(C)]
    #[derive(Default)]
    struct MapInfo {
        map_type: u32,
        id: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ElementAttr {
        map_fd: u32,
        padding: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    fn bpf<T>(command: u32, attr: &mut T) -> io::Result<libc::c_long> {
        // SAFETY: each caller supplies the repr(C) attribute for this command;
        // the kernel reads/writes it and its live pointees synchronously.
        let result =
            unsafe { libc::syscall(libc::SYS_bpf, command, attr as *mut T, size_of::<T>()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    pub(crate) struct PinnedHashMap {
        fd: OwnedFd,
        pub layout: MapLayout,
    }

    impl PinnedHashMap {
        pub fn open(path: &Path) -> io::Result<Self> {
            let path = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in BPF pin path"))?;
            let mut attr = ObjectAttr {
                pathname: path.as_ptr() as u64,
                ..Default::default()
            };
            let raw_fd = bpf(BPF_OBJ_GET, &mut attr)? as i32;
            // SAFETY: successful BPF_OBJ_GET returns a new descriptor owned by us.
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let mut info = MapInfo::default();
            let mut attr = InfoAttr {
                bpf_fd: fd.as_raw_fd() as u32,
                info_len: size_of::<MapInfo>() as u32,
                info: &mut info as *mut MapInfo as u64,
            };
            bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr)?;
            // Per-CPU maps require a differently-sized value buffer. Never
            // treat those (or map-in-map/queue types) as an ordinary hash map.
            if !matches!(info.map_type, 1 | 9)
                || info.key_size == 0
                || info.value_size == 0
                || info.max_entries == 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected nonempty HASH or LRU_HASH map",
                ));
            }
            Ok(Self {
                fd,
                layout: MapLayout {
                    key_size: info.key_size,
                    value_size: info.value_size,
                    max_entries: info.max_entries,
                },
            })
        }

        pub fn update(&self, key: &[u8], value: &[u8]) -> io::Result<()> {
            self.layout.validate(key, value)?;
            let mut attr = ElementAttr {
                map_fd: self.fd.as_raw_fd() as u32,
                key: key.as_ptr() as u64,
                value: value.as_ptr() as u64,
                ..Default::default()
            };
            bpf(BPF_MAP_UPDATE_ELEM, &mut attr)?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn attributes_match_kernel_abi() {
            assert_eq!(size_of::<ObjectAttr>(), 16);
            assert_eq!(size_of::<InfoAttr>(), 16);
            assert_eq!(size_of::<MapInfo>(), 24);
            assert_eq!(size_of::<ElementAttr>(), 32);
            assert_eq!(std::mem::offset_of!(ElementAttr, key), 8);
            assert_eq!(std::mem::offset_of!(ElementAttr, value), 16);
            assert_eq!(std::mem::offset_of!(ElementAttr, flags), 24);
        }
        #[test]
        fn rejects_nul_before_syscall() {
            assert!(
                matches!(PinnedHashMap::open(Path::new("/sys/fs/bpf/bad\0pin")), Err(e) if e.kind() == io::ErrorKind::InvalidInput)
            );
        }

        // Explicit opt-in: requires CAP_BPF (or CAP_SYS_ADMIN on older kernels).
        // This exercises the actual update syscall, with no bpffs mount needed.
        #[test]
        #[ignore = "requires a kernel allowing BPF_MAP_CREATE"]
        fn kernel_hash_map_roundtrip() {
            #[repr(C)]
            struct CreateAttr {
                map_type: u32,
                key_size: u32,
                value_size: u32,
                max_entries: u32,
                map_flags: u32,
            }
            let mut attr = CreateAttr {
                map_type: 9,
                key_size: 4,
                value_size: 8,
                max_entries: 2,
                map_flags: 0,
            };
            let fd =
                bpf(0, &mut attr).expect("BPF_MAP_CREATE requires kernel BPF permissions") as i32;
            // SAFETY: successful MAP_CREATE transfers a fresh descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let map = PinnedHashMap {
                fd,
                layout: MapLayout {
                    key_size: 4,
                    value_size: 8,
                    max_entries: 2,
                },
            };
            let key = 7u32.to_ne_bytes();
            map.update(&key, &42u64.to_ne_bytes()).unwrap();
            let mut value = [0u8; 8];
            let mut attr = ElementAttr {
                map_fd: map.fd.as_raw_fd() as u32,
                key: key.as_ptr() as u64,
                value: value.as_mut_ptr() as u64,
                ..Default::default()
            };
            bpf(1, &mut attr).unwrap();
            assert_eq!(u64::from_ne_bytes(value), 42);
            assert!(map.update(&key[..3], &value).is_err());
            assert!(map.layout.check_capacity(3).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::PinnedHashMap;

#[cfg(not(target_os = "linux"))]
pub(crate) struct PinnedHashMap {
    pub layout: MapLayout,
}
#[cfg(not(target_os = "linux"))]
impl PinnedHashMap {
    pub fn open(_: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "BPF maps require Linux",
        ))
    }
    pub fn update(&self, _: &[u8], _: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "BPF maps require Linux",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checks_sizes_before_kernel_reads_memory() {
        let layout = MapLayout {
            key_size: 44,
            value_size: 8,
            max_entries: 32768,
        };
        assert!(layout.validate(&[0; 44], &[0; 8]).is_ok());
        assert!(layout.validate(&[0; 43], &[0; 8]).is_err());
        assert!(layout.validate(&[0; 44], &[0; 7]).is_err());
        assert!(layout.check_capacity(32768).is_ok());
        assert!(layout.check_capacity(32769).is_err());
    }
}
