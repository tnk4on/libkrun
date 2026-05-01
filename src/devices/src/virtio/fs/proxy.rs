//! ProxyFs: Fetches files on-demand from a remote proxy-fsd server
//! over Unix socket (typically via vsock relay).
//!
//! No local caching. Every file access is a round-trip to proxy-fsd.
//! Designed for ephemeral VMs where files are read once.

use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::mem;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use proxy_fs_proto::*;

use super::super::bindings;
use super::super::linux_errno::linux_error;
use super::filesystem::{
    Context, DirEntry, Entry, FileSystem, FsOptions, OpenOptions, ZeroCopyWriter,
};
use super::fuse;

const LINUX_ENOENT: i32 = 2;
const LINUX_EIO: i32 = 5;
const LINUX_EBADF: i32 = 9;
const LINUX_EROFS: i32 = 30;

struct HandleData {
    inode: u64,
    dir_entries: Mutex<Option<Vec<(String, u32)>>>,
}

pub struct ProxyFs {
    socket_path: String,
    conn: Mutex<Option<UnixStream>>,
    listener: Mutex<Option<std::os::unix::net::UnixListener>>,
    inode_to_path: RwLock<HashMap<u64, String>>,
    path_to_inode: RwLock<HashMap<String, u64>>,
    next_inode: AtomicU64,
    handles: RwLock<BTreeMap<u64, Arc<HandleData>>>,
    next_handle: AtomicU64,
}

impl ProxyFs {
    pub fn new(socket_path: &str) -> io::Result<Self> {
        let fs = ProxyFs {
            socket_path: socket_path.to_string(),
            conn: Mutex::new(None),
            listener: Mutex::new(None),
            inode_to_path: RwLock::new(HashMap::new()),
            path_to_inode: RwLock::new(HashMap::new()),
            next_inode: AtomicU64::new(2),
            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
        };
        fs.inode_to_path.write().unwrap().insert(1, "/".to_string());
        fs.path_to_inode.write().unwrap().insert("/".to_string(), 1);
        Ok(fs)
    }

    pub fn new_listen(socket_path: &str) -> io::Result<Self> {
        let _ = std::fs::remove_file(socket_path);
        let listener = std::os::unix::net::UnixListener::bind(socket_path)?;
        log::info!("ProxyFs listening on {} (waiting for proxy-fsd)", socket_path);

        let fs = ProxyFs {
            socket_path: socket_path.to_string(),
            conn: Mutex::new(None),
            listener: Mutex::new(Some(listener)),
            inode_to_path: RwLock::new(HashMap::new()),
            path_to_inode: RwLock::new(HashMap::new()),
            next_inode: AtomicU64::new(2),
            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
        };
        fs.inode_to_path.write().unwrap().insert(1, "/".to_string());
        fs.path_to_inode.write().unwrap().insert("/".to_string(), 1);
        Ok(fs)
    }

    fn get_conn(&self) -> io::Result<std::sync::MutexGuard<'_, Option<UnixStream>>> {
        let mut conn = self.conn.lock().unwrap();
        if conn.is_none() {
            let listener = self.listener.lock().unwrap();
            if let Some(ref l) = *listener {
                log::info!("ProxyFs: waiting for proxy-fsd connection...");
                let (stream, _) = l.accept()?;
                log::info!("ProxyFs: proxy-fsd connected");
                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
                *conn = Some(stream);
            } else {
                *conn = Some(UnixStream::connect(&self.socket_path)?);
            }
        }
        Ok(conn)
    }

    fn alloc_inode(&self, path: &str) -> u64 {
        let p2i = self.path_to_inode.read().unwrap();
        if let Some(&ino) = p2i.get(path) {
            return ino;
        }
        drop(p2i);
        let mut p2i = self.path_to_inode.write().unwrap();
        if let Some(&ino) = p2i.get(path) {
            return ino;
        }
        let ino = self.next_inode.fetch_add(1, Ordering::Relaxed);
        p2i.insert(path.to_string(), ino);
        self.inode_to_path.write().unwrap().insert(ino, path.to_string());
        ino
    }

    fn get_path(&self, inode: u64) -> Option<String> {
        self.inode_to_path.read().unwrap().get(&inode).cloned()
    }

    fn child_path(parent: &str, name: &str) -> String {
        if parent == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent, name)
        }
    }

    fn fetch_stat(&self, rel_path: &str) -> io::Result<StatResponse> {
        let mut conn_guard = self.get_conn()?;
        let stream = conn_guard.as_mut().unwrap();
        write_op(stream, OP_STAT, rel_path)?;
        let status = read_u8(stream)?;
        if status != STATUS_OK {
            return Err(io::Error::from_raw_os_error(LINUX_ENOENT));
        }
        StatResponse::read_from(stream)
    }

    fn stat_to_stat64(remote: &StatResponse) -> bindings::stat64 {
        let mut st: bindings::stat64 = unsafe { mem::zeroed() };
        st.st_mode = remote.mode as u16;
        st.st_size = remote.size as i64;
        st.st_uid = remote.uid;
        st.st_gid = remote.gid;
        st.st_mtime = remote.mtime as i64;
        st.st_nlink = remote.nlink as u16;
        st.st_ino = remote.ino;
        st.st_blksize = 4096;
        st.st_blocks = ((remote.size + 511) / 512) as i64;
        st
    }

    fn fetch_readdir(&self, rel_path: &str) -> io::Result<Vec<(String, u32)>> {
        let mut conn_guard = self.get_conn()?;
        let stream = conn_guard.as_mut().unwrap();
        write_op(stream, OP_READDIR, rel_path)?;
        let status = read_u8(stream)?;
        if status != STATUS_OK {
            return Err(io::Error::from_raw_os_error(LINUX_ENOENT));
        }
        let count = read_u32(stream)? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let name_len = read_u32(stream)? as usize;
            let mut name_buf = vec![0u8; name_len];
            stream.read_exact(&mut name_buf)?;
            let name = String::from_utf8_lossy(&name_buf).into_owned();
            let ftype = read_u32(stream)?;
            entries.push((name, ftype));
        }
        for (name, _) in &entries {
            let child_path = Self::child_path(rel_path, name);
            self.alloc_inode(&child_path);
        }
        Ok(entries)
    }

    fn fetch_read_range(&self, rel_path: &str, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        const CHUNK: u32 = 32768;
        let mut result = Vec::with_capacity(size as usize);
        let mut cur_offset = offset;
        let mut remaining = size;
        let mut conn_guard = self.get_conn()?;
        let stream = conn_guard.as_mut().unwrap();
        while remaining > 0 {
            let chunk_size = std::cmp::min(remaining, CHUNK);
            write_op_range(stream, rel_path, cur_offset, chunk_size)?;
            let status = read_u8(stream)?;
            if status != STATUS_OK {
                if result.is_empty() {
                    return Err(io::Error::from_raw_os_error(LINUX_EIO));
                }
                break;
            }
            let data_len = read_u32(stream)? as usize;
            if data_len == 0 {
                break;
            }
            let prev_len = result.len();
            result.resize(prev_len + data_len, 0);
            stream.read_exact(&mut result[prev_len..])?;
            cur_offset += data_len as u64;
            remaining -= data_len as u32;
            if data_len < chunk_size as usize {
                break;
            }
        }
        Ok(result)
    }

    fn fetch_readlink(&self, rel_path: &str) -> io::Result<Vec<u8>> {
        let mut conn_guard = self.get_conn()?;
        let stream = conn_guard.as_mut().unwrap();
        write_op(stream, OP_READLINK, rel_path)?;
        let status = read_u8(stream)?;
        if status != STATUS_OK {
            return Err(io::Error::from_raw_os_error(LINUX_ENOENT));
        }
        let link_len = read_u32(stream)? as usize;
        let mut buf = vec![0u8; link_len];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn mode_to_dtype(mode: u32) -> u32 {
        match mode & 0o170000 {
            0o040000 => libc::DT_DIR as u32,
            0o120000 => libc::DT_LNK as u32,
            _ => libc::DT_REG as u32,
        }
    }
}

fn enoent() -> io::Error { io::Error::from_raw_os_error(LINUX_ENOENT) }
fn ebadf() -> io::Error { io::Error::from_raw_os_error(LINUX_EBADF) }
fn erofs() -> io::Error { io::Error::from_raw_os_error(LINUX_EROFS) }

impl FileSystem for ProxyFs {
    type Inode = u64;
    type Handle = u64;

    fn init(&self, _capable: FsOptions) -> io::Result<FsOptions> {
        Ok(FsOptions::empty())
    }

    fn destroy(&self) {}

    fn lookup(&self, _ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<Entry> {
        let parent_path = self.get_path(parent).ok_or_else(enoent)?;
        let child_name = name.to_str().map_err(|_| enoent())?;
        let child_path = Self::child_path(&parent_path, child_name);
        let remote = self.fetch_stat(&child_path)?;
        let ino = self.alloc_inode(&child_path);
        let st = Self::stat_to_stat64(&remote);
        Ok(Entry {
            inode: ino,
            generation: 0,
            attr: st,
            attr_flags: 0,
            attr_timeout: Duration::from_secs(86400),
            entry_timeout: Duration::from_secs(86400),
        })
    }

    fn forget(&self, _ctx: Context, _inode: Self::Inode, _count: u64) {}

    fn getattr(
        &self, _ctx: Context, inode: Self::Inode, _handle: Option<Self::Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        let path = self.get_path(inode).ok_or_else(enoent)?;
        let remote = self.fetch_stat(&path)?;
        Ok((Self::stat_to_stat64(&remote), Duration::from_secs(86400)))
    }

    fn readlink(&self, _ctx: Context, inode: Self::Inode) -> io::Result<Vec<u8>> {
        let path = self.get_path(inode).ok_or_else(enoent)?;
        self.fetch_readlink(&path)
    }

    fn open(
        &self, _ctx: Context, inode: Self::Inode, _kill_priv: bool, _flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = Arc::new(HandleData {
            inode,
            dir_entries: Mutex::new(None),
        });
        self.handles.write().unwrap().insert(handle, data);
        Ok((Some(handle), OpenOptions::KEEP_CACHE))
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self, _ctx: Context, inode: Self::Inode, handle: Self::Handle, mut w: W,
        size: u32, offset: u64, _lock_owner: Option<u64>, _flags: u32,
    ) -> io::Result<usize> {
        self.handles.read().unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .ok_or_else(ebadf)?;

        let path = self.get_path(inode).ok_or_else(enoent)?;
        let data = self.fetch_read_range(&path, offset, size)?;
        if data.is_empty() {
            return Ok(0);
        }
        w.write_all(&data)?;
        Ok(data.len())
    }

    fn release(
        &self, _ctx: Context, _inode: Self::Inode, _flags: u32, handle: Self::Handle,
        _flush: bool, _flock_release: bool, _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.handles.write().unwrap().remove(&handle);
        Ok(())
    }

    fn statfs(&self, _ctx: Context, _inode: Self::Inode) -> io::Result<bindings::statvfs64> {
        let mut st: bindings::statvfs64 = unsafe { mem::zeroed() };
        st.f_namemax = 255;
        st.f_bsize = 4096;
        st.f_frsize = 4096;
        st.f_flag = libc::ST_RDONLY as u64;
        Ok(st)
    }

    fn opendir(
        &self, _ctx: Context, inode: Self::Inode, _flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        let path = self.get_path(inode).ok_or_else(enoent)?;
        let entries = self.fetch_readdir(&path)?;
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = Arc::new(HandleData {
            inode,
            dir_entries: Mutex::new(Some(entries)),
        });
        self.handles.write().unwrap().insert(handle, data);
        Ok((Some(handle), OpenOptions::KEEP_CACHE))
    }

    fn readdir<F>(
        &self, _ctx: Context, inode: Self::Inode, handle: Self::Handle,
        _size: u32, offset: u64, mut add_entry: F,
    ) -> io::Result<()>
    where F: FnMut(DirEntry) -> io::Result<usize> {
        let data = self.handles.read().unwrap()
            .get(&handle).filter(|hd| hd.inode == inode)
            .cloned().ok_or_else(ebadf)?;
        let guard = data.dir_entries.lock().unwrap();
        let entries = guard.as_ref().ok_or_else(ebadf)?;
        let parent_path = self.get_path(inode).ok_or_else(enoent)?;
        for (i, (name, ftype)) in entries.iter().enumerate() {
            let entry_offset = (i + 1) as u64;
            if entry_offset <= offset { continue; }
            let child_path = Self::child_path(&parent_path, name);
            let child_ino = self.alloc_inode(&child_path);
            match add_entry(DirEntry {
                ino: child_ino, offset: entry_offset,
                type_: Self::mode_to_dtype(*ftype), name: name.as_bytes(),
            }) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn releasedir(
        &self, _ctx: Context, _inode: Self::Inode, _flags: u32, handle: Self::Handle,
    ) -> io::Result<()> {
        self.handles.write().unwrap().remove(&handle);
        Ok(())
    }

    fn access(&self, _ctx: Context, _inode: Self::Inode, _mask: u32) -> io::Result<()> {
        Ok(())
    }

    // Write operations → EROFS

    fn setattr(&self, _ctx: Context, _inode: Self::Inode, _attr: bindings::stat64,
        _handle: Option<Self::Handle>, _valid: fuse::SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> { Err(erofs()) }

    fn mkdir(&self, _ctx: Context, _parent: Self::Inode, _name: &CStr, _mode: u32,
        _umask: u32, _ext: super::filesystem::Extensions,
    ) -> io::Result<Entry> { Err(erofs()) }

    fn unlink(&self, _ctx: Context, _p: Self::Inode, _n: &CStr) -> io::Result<()> { Err(erofs()) }
    fn rmdir(&self, _ctx: Context, _p: Self::Inode, _n: &CStr) -> io::Result<()> { Err(erofs()) }

    fn rename(&self, _ctx: Context, _od: Self::Inode, _on: &CStr,
        _nd: Self::Inode, _nn: &CStr, _flags: u32,
    ) -> io::Result<()> { Err(erofs()) }

    fn link(&self, _ctx: Context, _i: Self::Inode, _np: Self::Inode, _nn: &CStr,
    ) -> io::Result<Entry> { Err(erofs()) }

    fn symlink(&self, _ctx: Context, _ln: &CStr, _p: Self::Inode, _n: &CStr,
        _ext: super::filesystem::Extensions,
    ) -> io::Result<Entry> { Err(erofs()) }

    fn mknod(&self, _ctx: Context, _p: Self::Inode, _n: &CStr, _mode: u32,
        _rdev: u32, _umask: u32, _ext: super::filesystem::Extensions,
    ) -> io::Result<Entry> { Err(erofs()) }

    fn create(&self, _ctx: Context, _p: Self::Inode, _n: &CStr, _mode: u32,
        _kp: bool, _flags: u32, _umask: u32, _ext: super::filesystem::Extensions,
    ) -> io::Result<(Entry, Option<Self::Handle>, OpenOptions)> { Err(erofs()) }

    fn write<R: io::Read + super::filesystem::ZeroCopyReader>(
        &self, _ctx: Context, _i: Self::Inode, _h: Self::Handle, _r: R,
        _size: u32, _off: u64, _lo: Option<u64>, _dw: bool, _kp: bool, _flags: u32,
    ) -> io::Result<usize> { Err(erofs()) }
}
