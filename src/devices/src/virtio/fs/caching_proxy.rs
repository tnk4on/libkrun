//! CachingProxyFs: Fetches files on-demand from remote bcvk-fsd server,
//! caches locally, and serves from cache for subsequent accesses.
//!
//! Cache hits use local filesystem (DAX-compatible via setupmapping).
//! Cache misses fetch via Unix socket from bcvk-fsd running in podman-machine.

use std::collections::HashMap;
use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use super::filesystem::{
    Context, DirEntry, Entry, FileSystem, GetxattrReply, ListxattrReply, OpenOptions,
};

// bcvk-fsd protocol opcodes
const OP_STAT: u8 = 1;
const OP_READ: u8 = 2;
const OP_READDIR: u8 = 3;
const OP_READLINK: u8 = 4;
const STATUS_OK: u8 = 0;

/// A FUSE filesystem that caches remote files locally.
pub struct CachingProxyFs {
    cache_dir: PathBuf,
    socket_path: String,
    conn: Mutex<Option<UnixStream>>,
    // Map from our inode to cached relative path
    inode_to_path: Mutex<HashMap<u64, String>>,
    path_to_inode: Mutex<HashMap<String, u64>>,
    next_inode: Mutex<u64>,
}

impl CachingProxyFs {
    /// Create a new CachingProxyFs.
    ///
    /// * `cache_dir` - Local directory for caching files
    /// * `socket_path` - Path to bcvk-fsd Unix socket
    pub fn new(cache_dir: &str, socket_path: &str) -> io::Result<Self> {
        std::fs::create_dir_all(cache_dir)?;
        let fs = CachingProxyFs {
            cache_dir: PathBuf::from(cache_dir),
            socket_path: socket_path.to_string(),
            conn: Mutex::new(None),
            inode_to_path: Mutex::new(HashMap::new()),
            path_to_inode: Mutex::new(HashMap::new()),
            next_inode: Mutex::new(2), // 1 = root
        };

        // Register root inode
        fs.inode_to_path.lock().unwrap().insert(1, "/".to_string());
        fs.path_to_inode.lock().unwrap().insert("/".to_string(), 1);

        Ok(fs)
    }

    fn connect(&self) -> io::Result<UnixStream> {
        let mut conn = self.conn.lock().unwrap();
        if let Some(ref c) = *conn {
            if let Ok(cloned) = c.try_clone() {
                return Ok(cloned);
            }
        }
        let stream = UnixStream::connect(&self.socket_path)?;
        *conn = Some(stream.try_clone()?);
        Ok(stream)
    }

    fn alloc_inode(&self, path: &str) -> u64 {
        let mut p2i = self.path_to_inode.lock().unwrap();
        if let Some(&ino) = p2i.get(path) {
            return ino;
        }
        let mut next = self.next_inode.lock().unwrap();
        let ino = *next;
        *next += 1;
        p2i.insert(path.to_string(), ino);
        self.inode_to_path.lock().unwrap().insert(ino, path.to_string());
        ino
    }

    fn get_path(&self, inode: u64) -> Option<String> {
        self.inode_to_path.lock().unwrap().get(&inode).cloned()
    }

    fn cache_path(&self, rel_path: &str) -> PathBuf {
        self.cache_dir.join(rel_path.trim_start_matches('/'))
    }

    /// Ensure a file is cached locally. Returns local path.
    fn ensure_cached(&self, rel_path: &str) -> io::Result<PathBuf> {
        let local = self.cache_path(rel_path);
        if local.exists() {
            return Ok(local);
        }

        // Fetch from remote
        let mut stream = self.connect()?;

        // STAT first to know type
        write_op(&mut stream, OP_STAT, rel_path)?;
        let status = read_u8(&mut stream)?;
        if status != STATUS_OK {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        let mode = read_u32(&mut stream)?;
        let _size = read_u64(&mut stream)?;
        let _uid = read_u32(&mut stream)?;
        let _gid = read_u32(&mut stream)?;
        let _mtime = read_u64(&mut stream)?;
        let _nlink = read_u64(&mut stream)?;
        let _ino = read_u64(&mut stream)?;

        let is_dir = (mode & 0o170000) == 0o040000;
        let is_link = (mode & 0o170000) == 0o120000;

        if is_dir {
            std::fs::create_dir_all(&local)?;
        } else if is_link {
            // Fetch link target
            write_op(&mut stream, OP_READLINK, rel_path)?;
            let status = read_u8(&mut stream)?;
            if status == STATUS_OK {
                let link_len = read_u32(&mut stream)? as usize;
                let mut buf = vec![0u8; link_len];
                stream.read_exact(&mut buf)?;
                let target = String::from_utf8_lossy(&buf).into_owned();
                if let Some(parent) = local.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let _ = std::fs::remove_file(&local);
                std::os::unix::fs::symlink(&target, &local)?;
            }
        } else {
            // Regular file - fetch content
            write_op(&mut stream, OP_READ, rel_path)?;
            let status = read_u8(&mut stream)?;
            if status == STATUS_OK {
                let data_len = read_u64(&mut stream)? as usize;
                let mut data = vec![0u8; data_len];
                stream.read_exact(&mut data)?;
                if let Some(parent) = local.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&local, &data)?;
                // Set permissions
                std::fs::set_permissions(&local, std::fs::Permissions::from_mode(mode))?;
            }
        }

        Ok(local)
    }

    /// Ensure directory entries are cached.
    fn ensure_dir_cached(&self, rel_path: &str) -> io::Result<Vec<(String, u32)>> {
        let mut stream = self.connect()?;
        write_op(&mut stream, OP_READDIR, rel_path)?;
        let status = read_u8(&mut stream)?;
        if status != STATUS_OK {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        let count = read_u32(&mut stream)? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let name_len = read_u32(&mut stream)? as usize;
            let mut name_buf = vec![0u8; name_len];
            stream.read_exact(&mut name_buf)?;
            let name = String::from_utf8_lossy(&name_buf).into_owned();
            let ftype = read_u32(&mut stream)?;
            entries.push((name, ftype));
        }

        // Create directory locally and register inodes
        let local_dir = self.cache_path(rel_path);
        std::fs::create_dir_all(&local_dir)?;

        for (name, _ftype) in &entries {
            let child_path = if rel_path == "/" {
                format!("/{}", name)
            } else {
                format!("{}/{}", rel_path, name)
            };
            self.alloc_inode(&child_path);
        }

        Ok(entries)
    }
}

// Protocol helpers
fn write_op(stream: &mut UnixStream, op: u8, path: &str) -> io::Result<()> {
    stream.write_all(&[op])?;
    let path_bytes = path.as_bytes();
    stream.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
    stream.write_all(path_bytes)?;
    stream.flush()
}

fn read_u8(stream: &mut UnixStream) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u32(stream: &mut UnixStream) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64(stream: &mut UnixStream) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

use std::os::unix::fs::PermissionsExt;

// FileSystem trait implementation is complex (50+ methods).
// For now, this file defines the core structure and protocol client.
// The full FileSystem impl will delegate to local PassthroughFs for cached files.
//
// TODO: Implement FileSystem trait with:
//   - lookup: alloc_inode + ensure_cached
//   - getattr: stat from cache
//   - open/read: ensure_cached + local read
//   - readdir: ensure_dir_cached
//   - readlink: ensure_cached (symlink)
//   - setupmapping: delegate to local cache file (DAX support)
