// A virtio-fs device served by the embedder rather than from a host directory.
//
// `ExternalFs` is what the embedder implements: a read-only tree, inode by inode, in plain
// types. `External` adapts it to this crate's `FileSystem`, which the server drives.

use std::ffi::CStr;
use std::io;
use std::mem;
use std::sync::Arc;
use std::time::Duration;

use super::bindings;
use super::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, OpenOptions, SetattrValid,
    ZeroCopyWriter,
};
use super::fuse;
#[cfg(target_os = "windows")]
use super::windows::{fs_utils, passthrough};

/// How long the guest may cache what it was told about an inode.
const TIMEOUT: Duration = Duration::from_secs(1);

/// What an inode is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalAttr {
    pub ino: u64,
    pub dir: bool,
    pub size: u64,
    /// When the contents last changed, since the Unix epoch.
    pub modified: Duration,
}

/// One entry of a directory listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalEntry {
    pub ino: u64,
    pub dir: bool,
    pub name: Vec<u8>,
    /// Where a listing that stops after this entry resumes.
    pub offset: u64,
}

/// A read-only tree the embedder serves. Inode 1 is its root. An error carries the host's
/// errno, as `io::Error::from_raw_os_error` makes one.
pub trait ExternalFs: Send + Sync {
    /// The entry `name` in directory `parent`: one more reference to its inode, which the
    /// guest gives back through [`forget`](Self::forget).
    fn lookup(&self, parent: u64, name: &[u8]) -> io::Result<ExternalAttr>;

    /// The guest let go of `count` references to `ino`.
    fn forget(&self, ino: u64, count: u64);

    fn getattr(&self, ino: u64) -> io::Result<ExternalAttr>;

    /// The entries of directory `ino` from `offset`, `0` being its start; fewer than all is
    /// fine, the guest asks again from the last one's offset.
    fn readdir(&self, ino: u64, offset: u64) -> io::Result<Vec<ExternalEntry>>;

    /// Up to `size` bytes of file `ino` from `offset`; fewer only at its end.
    fn read(&self, ino: u64, offset: u64, size: u32) -> io::Result<Vec<u8>>;
}

pub(crate) struct External(pub Arc<dyn ExternalFs>);

fn stat(attr: &ExternalAttr) -> bindings::stat64 {
    // Safe because we are zero-initializing a struct with only POD fields.
    let mut st: bindings::stat64 = unsafe { mem::zeroed() };
    st.st_ino = attr.ino as _;
    let kind = if attr.dir {
        libc::S_IFDIR
    } else {
        libc::S_IFREG
    };
    let perm = if attr.dir { 0o555 } else { 0o444 };
    st.st_mode = (kind as u32 | perm) as _;
    st.st_nlink = if attr.dir { 2 } else { 1 };
    st.st_size = attr.size as _;
    st.st_blksize = 4096;
    st.st_blocks = attr.size.div_ceil(512) as _;
    st.st_mtime = attr.modified.as_secs() as _;
    st.st_mtime_nsec = attr.modified.subsec_nanos() as _;
    st.st_ctime = st.st_mtime;
    st.st_ctime_nsec = st.st_mtime_nsec;
    st.st_atime = st.st_mtime;
    st.st_atime_nsec = st.st_mtime_nsec;
    st
}

fn read_only() -> io::Error {
    io::Error::from_raw_os_error(libc::EROFS)
}

impl FileSystem for External {
    type Inode = u64;
    type Handle = u64;

    fn init(&self, _capable: FsOptions) -> io::Result<FsOptions> {
        Ok(FsOptions::empty())
    }

    fn lookup(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        let attr = self.0.lookup(parent, name.to_bytes())?;
        Ok(Entry {
            inode: attr.ino,
            generation: 0,
            attr: stat(&attr),
            attr_flags: 0,
            attr_timeout: TIMEOUT,
            entry_timeout: TIMEOUT,
        })
    }

    fn forget(&self, _ctx: Context, inode: u64, count: u64) {
        self.0.forget(inode, count);
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(u64, u64)>) {
        for (inode, count) in requests {
            self.forget(ctx, inode, count);
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: u64,
        _handle: Option<u64>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        Ok((stat(&self.0.getattr(inode)?), TIMEOUT))
    }

    fn opendir(
        &self,
        _ctx: Context,
        _inode: u64,
        _flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        Ok((Some(0), OpenOptions::empty()))
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: u64,
        _handle: u64,
        _size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        #[cfg(not(target_os = "windows"))]
        let (dt_dir, dt_reg) = (libc::DT_DIR as u32, libc::DT_REG as u32);
        #[cfg(target_os = "windows")]
        let (dt_dir, dt_reg) = (passthrough::DT_DIR, passthrough::DT_REG);
        for entry in self.0.readdir(inode, offset)? {
            let added = add_entry(DirEntry {
                ino: entry.ino as _,
                offset: entry.offset,
                type_: if entry.dir { dt_dir } else { dt_reg },
                name: &entry.name,
            })?;
            // The guest's buffer is full; it asks again from here.
            if added == 0 {
                break;
            }
        }
        Ok(())
    }

    fn releasedir(&self, _ctx: Context, _inode: u64, _flags: u32, _handle: u64) -> io::Result<()> {
        Ok(())
    }

    fn open(
        &self,
        _ctx: Context,
        _inode: u64,
        _kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        #[cfg(not(target_os = "windows"))]
        let o_accmode = libc::O_ACCMODE;
        #[cfg(target_os = "windows")]
        let o_accmode = fs_utils::O_ACCMODE;
        if flags as i32 & o_accmode != libc::O_RDONLY {
            return Err(read_only());
        }
        Ok((Some(0), OpenOptions::empty()))
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: u64,
        _handle: u64,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self.0.read(inode, offset, size)?;
        w.write_all(&data)?;
        Ok(data.len())
    }

    fn release(
        &self,
        _ctx: Context,
        _inode: u64,
        _flags: u32,
        _handle: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn setattr(
        &self,
        _ctx: Context,
        _inode: u64,
        _attr: bindings::stat64,
        _handle: Option<u64>,
        _valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        Err(read_only())
    }

    fn symlink(
        &self,
        _ctx: Context,
        _linkname: &CStr,
        _parent: u64,
        _name: &CStr,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(read_only())
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        _ctx: Context,
        _inode: u64,
        _name: &CStr,
        _mode: u32,
        _rdev: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(read_only())
    }

    fn mkdir(
        &self,
        _ctx: Context,
        _parent: u64,
        _name: &CStr,
        _mode: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(read_only())
    }

    fn unlink(&self, _ctx: Context, _parent: u64, _name: &CStr) -> io::Result<()> {
        Err(read_only())
    }

    fn rmdir(&self, _ctx: Context, _parent: u64, _name: &CStr) -> io::Result<()> {
        Err(read_only())
    }

    fn rename(
        &self,
        _ctx: Context,
        _olddir: u64,
        _oldname: &CStr,
        _newdir: u64,
        _newname: &CStr,
        _flags: u32,
    ) -> io::Result<()> {
        Err(read_only())
    }

    fn link(
        &self,
        _ctx: Context,
        _inode: u64,
        _newparent: u64,
        _newname: &CStr,
    ) -> io::Result<Entry> {
        Err(read_only())
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        _ctx: Context,
        _parent: u64,
        _name: &CStr,
        _mode: u32,
        _kill_priv: bool,
        _flags: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        Err(read_only())
    }

    fn access(&self, _ctx: Context, _inode: u64, mask: u32) -> io::Result<()> {
        #[cfg(not(target_os = "windows"))]
        let w_ok = libc::W_OK;
        #[cfg(target_os = "windows")]
        let w_ok = fs_utils::W_OK;
        if mask & w_ok as u32 != 0 {
            return Err(read_only());
        }
        Ok(())
    }
}

const _: () = assert!(fuse::ROOT_ID == 1);
