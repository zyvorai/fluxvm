// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Apply OCI image layers to a directory: decompress, verify the diff_id, honour whiteouts, and never write
//! outside the root, even through symlinks planted by earlier layers.

use std::collections::{HashSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::config::Compression;

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";
const MAX_SYMLINK_HOPS: usize = 40;

/// What the unpacker may do beyond plain files; the builder VM runs as root and enables all of it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub preserve_owner: bool,
    pub special_files: bool,
    pub xattrs: bool,
}

impl Options {
    pub fn privileged() -> Self {
        Self {
            preserve_owner: true,
            special_files: true,
            xattrs: true,
        }
    }
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Apply one layer blob and return the `sha256:` digest of its uncompressed tar (to compare with the diff_id).
pub fn apply_layer<'a, R: Read + 'a>(
    root: &Path,
    blob: R,
    compression: Compression,
    opts: &Options,
) -> Result<String> {
    let decoded: Box<dyn Read + 'a> = match compression {
        Compression::None => Box::new(blob),
        Compression::Gzip => Box::new(flate2::read::GzDecoder::new(blob)),
        Compression::Zstd => Box::new(zstd::stream::read::Decoder::new(blob)?),
    };
    let mut hashing = HashingReader {
        inner: decoded,
        hasher: Sha256::new(),
    };
    let mut created = HashSet::new();
    {
        let mut archive = tar::Archive::new(&mut hashing);
        for entry in archive.entries().context("reading layer tar")? {
            let mut entry = entry.context("reading layer tar entry")?;
            let shown = entry
                .path()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            apply_entry(root, &mut entry, opts, &mut created)
                .with_context(|| format!("layer entry {shown:?}"))?;
        }
    }
    // The diff_id covers the whole stream, including the end-of-archive padding tar stops short of.
    io::copy(&mut hashing, &mut io::sink())?;
    Ok(format!("sha256:{:x}", hashing.hasher.finalize()))
}

/// Archive path to a relative path; absolute and `./` prefixes are dropped, `..` is refused.
fn normalize(p: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                bail!("path {} leaves the image root", p.display())
            }
        }
    }
    Ok(out)
}

fn parts(p: &Path) -> VecDeque<OsString> {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_os_string()),
            Component::ParentDir => Some("..".into()),
            _ => None,
        })
        .collect()
}

/// Resolve `rel` under `root` following symlinks as the container would see them: absolute targets restart at
/// `root` and `..` stops at `root`, so the result is always inside `root`.
pub fn secure_join(root: &Path, rel: &Path) -> Result<PathBuf> {
    let mut todo = parts(rel);
    let mut cur: Vec<OsString> = Vec::new();
    let mut hops = 0;
    while let Some(c) = todo.pop_front() {
        if c == ".." {
            cur.pop();
            continue;
        }
        let candidate: PathBuf = std::iter::once(root.as_os_str())
            .chain(cur.iter().map(|s| s.as_os_str()))
            .chain(std::iter::once(c.as_os_str()))
            .collect();
        match fs::symlink_metadata(&candidate) {
            Ok(m) if m.file_type().is_symlink() => {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    bail!("too many symlinks resolving {}", rel.display());
                }
                let target = fs::read_link(&candidate)?;
                if target.is_absolute() {
                    cur.clear();
                }
                let mut next = parts(&target);
                next.extend(todo);
                todo = next;
            }
            _ => cur.push(c),
        }
    }
    let mut out = root.to_path_buf();
    out.extend(cur);
    Ok(out)
}

fn remove_any(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn apply_entry<R: Read>(
    root: &Path,
    entry: &mut tar::Entry<R>,
    opts: &Options,
    created: &mut HashSet<PathBuf>,
) -> Result<()> {
    let rel = normalize(&entry.path()?)?;
    let Some(name) = rel.file_name().map(|n| n.to_os_string()) else {
        return Ok(());
    };
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    let parent = secure_join(root, parent_rel)?;
    let name_str = name.to_string_lossy();

    if name_str == OPAQUE {
        if fs::symlink_metadata(&parent).is_ok_and(|m| m.is_dir()) {
            for child in fs::read_dir(&parent)? {
                let child = child?.path();
                if !created.contains(&child) {
                    remove_any(&child)?;
                }
            }
        }
        return Ok(());
    }
    if let Some(hidden) = name_str.strip_prefix(WHITEOUT_PREFIX) {
        if hidden.is_empty() || hidden == "." || hidden == ".." || hidden.contains('/') {
            bail!("malformed whiteout {name_str:?}");
        }
        remove_any(&parent.join(hidden))?;
        return Ok(());
    }

    fs::create_dir_all(&parent)?;
    let target = parent.join(&name);
    let kind = entry.header().entry_type();
    let existing = fs::symlink_metadata(&target).ok();
    if kind.is_dir() {
        if existing.as_ref().is_some_and(|m| !m.is_dir()) {
            remove_any(&target)?;
        }
    } else if existing.is_some() {
        remove_any(&target)?;
    }

    use tar::EntryType as T;
    match kind {
        T::Directory => {
            if !target.is_dir() {
                fs::create_dir(&target)?;
            }
        }
        T::Regular | T::Continuous | T::GNUSparse => {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            let want = entry.size();
            if io::copy(entry, &mut f)? != want {
                bail!("truncated file data");
            }
        }
        T::Symlink => {
            let link = entry.link_name()?.context("symlink without a target")?;
            std::os::unix::fs::symlink(&*link, &target)?;
        }
        T::Link => {
            let link = normalize(&entry.link_name()?.context("hard link without a target")?)?;
            let link_parent = secure_join(root, link.parent().unwrap_or(Path::new("")))?;
            let source = link_parent.join(link.file_name().context("hard link to the root")?);
            fs::hard_link(&source, &target)
                .with_context(|| format!("hard link to {}", link.display()))?;
            created.insert(target);
            return Ok(());
        }
        T::Char | T::Block | T::Fifo => {
            if !opts.special_files {
                return Ok(());
            }
            make_special(&target, entry.header(), kind)?;
        }
        _ => return Ok(()),
    }

    let header = entry.header();
    let mode = header.mode()? & 0o7777;
    if opts.preserve_owner {
        let (uid, gid) = (header.uid()? as u32, header.gid()? as u32);
        lchown(&target, uid, gid)?;
    }
    if kind != T::Symlink {
        fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
    }
    if opts.xattrs {
        set_xattrs(&target, entry)?;
    }
    set_mtime(&target, entry.header().mtime().unwrap_or(0))?;
    created.insert(target);
    Ok(())
}

fn cpath(p: &Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    Ok(std::ffi::CString::new(p.as_os_str().as_bytes())?)
}

fn lchown(p: &Path, uid: u32, gid: u32) -> Result<()> {
    let c = cpath(p)?;
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error()).context("lchown");
    }
    Ok(())
}

fn make_special(p: &Path, header: &tar::Header, kind: tar::EntryType) -> Result<()> {
    let c = cpath(p)?;
    if kind == tar::EntryType::Fifo {
        if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
            return Err(io::Error::last_os_error()).context("mkfifo");
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let major = header.device_major()?.unwrap_or(0);
        let minor = header.device_minor()?.unwrap_or(0);
        let fmt = if kind == tar::EntryType::Char {
            libc::S_IFCHR
        } else {
            libc::S_IFBLK
        };
        if unsafe { libc::mknod(c.as_ptr(), fmt | 0o600, libc::makedev(major, minor)) } != 0 {
            return Err(io::Error::last_os_error()).context("mknod");
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = header;
        bail!("device nodes are only created in the Linux builder VM")
    }
}

fn set_xattrs<R: Read>(p: &Path, entry: &mut tar::Entry<R>) -> Result<()> {
    let Some(exts) = entry.pax_extensions()? else {
        return Ok(());
    };
    for ext in exts {
        let ext = ext?;
        let Some(name) = ext.key().ok().and_then(|k| k.strip_prefix("SCHILY.xattr.")) else {
            continue;
        };
        set_xattr(p, name, ext.value_bytes())?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_xattr(p: &Path, name: &str, value: &[u8]) -> Result<()> {
    let c = cpath(p)?;
    let n = std::ffi::CString::new(name)?;
    let rc = unsafe {
        libc::lsetxattr(
            c.as_ptr(),
            n.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        // ext4 without the namespace (or a filesystem without xattrs) should not sink the whole image.
        if e.raw_os_error() != Some(libc::ENOTSUP) {
            return Err(e).with_context(|| format!("setting xattr {name}"));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_xattr(_p: &Path, _name: &str, _value: &[u8]) -> Result<()> {
    Ok(())
}

fn set_mtime(p: &Path, mtime: u64) -> Result<()> {
    let c = cpath(p)?;
    let t = libc::timespec {
        tv_sec: mtime as libc::time_t,
        tv_nsec: 0,
    };
    let times = [t, t];
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("utimensat");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    enum E<'a> {
        Dir(&'a str),
        File(&'a str, &'a str),
        Sym(&'a str, &'a str),
        Hard(&'a str, &'a str),
        RawName(&'a str),
    }

    fn layer(entries: &[E]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for e in entries {
            let mut h = tar::Header::new_gnu();
            h.set_mtime(1_700_000_000);
            match e {
                E::Dir(p) => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_mode(0o755);
                    h.set_size(0);
                    h.set_path(p).unwrap();
                    h.set_cksum();
                    b.append(&h, io::empty()).unwrap();
                }
                E::File(p, body) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_mode(0o644);
                    h.set_size(body.len() as u64);
                    h.set_path(p).unwrap();
                    h.set_cksum();
                    b.append(&h, body.as_bytes()).unwrap();
                }
                E::Sym(p, to) | E::Hard(p, to) => {
                    let t = if matches!(e, E::Sym(..)) {
                        tar::EntryType::Symlink
                    } else {
                        tar::EntryType::Link
                    };
                    h.set_entry_type(t);
                    h.set_mode(0o777);
                    h.set_size(0);
                    h.set_path(p).unwrap();
                    h.set_link_name(to).unwrap();
                    h.set_cksum();
                    b.append(&h, io::empty()).unwrap();
                }
                E::RawName(p) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_mode(0o644);
                    h.set_size(0);
                    let name = &mut h.as_old_mut().name;
                    name[..p.len()].copy_from_slice(p.as_bytes());
                    h.set_cksum();
                    b.append(&h, io::empty()).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }

    fn sha(b: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(b))
    }

    fn apply(root: &Path, tar: &[u8], c: Compression) -> Result<String> {
        apply_layer(root, tar, c, &Options::default())
    }

    #[test]
    fn layers_stack_with_whiteouts_and_opaque_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let l1 = layer(&[
            E::Dir("etc/"),
            E::File("etc/passwd", "root:x:0:0::/root:/bin/sh\n"),
            E::Dir("app/"),
            E::File("app/a", "a"),
            E::File("app/b", "b"),
            E::Dir("keep/"),
            E::File("keep/x", "x"),
            E::File("keep/y", "y"),
            E::Dir("usr/bin/"),
            E::File("usr/bin/tool", "t"),
            E::Sym("bin", "usr/bin"),
        ]);
        assert_eq!(apply(root, &l1, Compression::None).unwrap(), sha(&l1));

        let l2 = layer(&[
            E::File("keep/.wh.x", ""),
            E::File("app/new", "n"),
            E::File("app/.wh..wh..opq", ""),
            E::File("bin/tool2", "t2"),
            E::Hard("etc/passwd2", "etc/passwd"),
        ]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&l2).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(apply(root, &gz, Compression::Gzip).unwrap(), sha(&l2));

        assert!(!root.join("keep/x").exists());
        assert!(root.join("keep/y").exists());
        assert!(!root.join("app/a").exists() && !root.join("app/b").exists());
        assert_eq!(fs::read_to_string(root.join("app/new")).unwrap(), "n");
        assert_eq!(
            fs::read_to_string(root.join("usr/bin/tool2")).unwrap(),
            "t2"
        );
        assert!(
            fs::symlink_metadata(root.join("bin"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(root.join("etc/passwd2")).unwrap(),
            "root:x:0:0::/root:/bin/sh\n"
        );
        assert!(!root.join(".wh.x").exists() && !root.join("app/.wh..wh..opq").exists());
    }

    #[test]
    fn symlinks_cannot_escape_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        let l = layer(&[
            E::Sym("abs", "/"),
            E::Sym("up", "../../../.."),
            E::Sym("loop", "loop"),
            E::File("abs/escaped-abs", "1"),
            E::File("up/escaped-up", "2"),
        ]);
        apply(&root, &l, Compression::None).unwrap();
        assert_eq!(fs::read_to_string(root.join("escaped-abs")).unwrap(), "1");
        assert_eq!(fs::read_to_string(root.join("escaped-up")).unwrap(), "2");
        assert!(!dir.path().join("escaped-up").exists());

        assert!(apply(&root, &layer(&[E::File("loop/x", "")]), Compression::None).is_err());
        assert!(apply(&root, &layer(&[E::RawName("../evil")]), Compression::None).is_err());
        assert!(!dir.path().join("evil").exists());
        assert!(
            apply(
                &root,
                &layer(&[E::Hard("h", "../../etc/hosts")]),
                Compression::None
            )
            .is_err()
        );
    }

    #[test]
    fn types_replace_each_other_and_zstd_works() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        apply(
            root,
            &layer(&[E::Dir("d/"), E::File("d/f", "x"), E::File("f", "y")]),
            Compression::None,
        )
        .unwrap();
        let l2 = layer(&[E::File("d", "now a file"), E::Dir("f/"), E::Sym("s", "d")]);
        let z = zstd::encode_all(&l2[..], 1).unwrap();
        assert_eq!(apply(root, &z, Compression::Zstd).unwrap(), sha(&l2));
        assert_eq!(fs::read_to_string(root.join("d")).unwrap(), "now a file");
        assert!(root.join("f").is_dir());
        assert_eq!(fs::read_link(root.join("s")).unwrap(), Path::new("d"));
    }

    #[test]
    fn corrupt_streams_fail() {
        let dir = tempfile::tempdir().unwrap();
        assert!(apply(dir.path(), b"definitely not gzip", Compression::Gzip).is_err());
        let l = layer(&[E::File("a", &"z".repeat(4096))]);
        assert!(apply(dir.path(), &l[..1024], Compression::None).is_err());
    }
}
