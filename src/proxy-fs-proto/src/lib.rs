//! Wire protocol for proxy-fs: lightweight file serving over vsock/unix socket.
//!
//! Used by proxy-fsd (server, runs inside VM) and ProxyFs (client, runs in libkrun).
//!
//! Protocol: request = [op:u8][path_len:u32le][path_bytes]
//! Response varies by operation (see each OP_* constant).

use std::io::{self, Read, Write};

// Opcodes
pub const OP_STAT: u8 = 1;
pub const OP_READ: u8 = 2;
pub const OP_READDIR: u8 = 3;
pub const OP_READLINK: u8 = 4;
pub const OP_READ_RANGE: u8 = 5;

// Response status
pub const STATUS_OK: u8 = 0;
pub const STATUS_ENOENT: u8 = 1;
pub const STATUS_EACCES: u8 = 2;
pub const STATUS_ERROR: u8 = 255;

// File type flags (matching Linux stat mode)
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

/// Send a request: [op][path_len:u32le][path_bytes]
pub fn write_op(w: &mut impl Write, op: u8, path: &str) -> io::Result<()> {
    w.write_all(&[op])?;
    let path_bytes = path.as_bytes();
    w.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
    w.write_all(path_bytes)?;
    w.flush()
}

/// Send a range-read request: [op][path_len:u32le][path_bytes][offset:u64le][size:u32le]
pub fn write_op_range(w: &mut impl Write, path: &str, offset: u64, size: u32) -> io::Result<()> {
    w.write_all(&[OP_READ_RANGE])?;
    let path_bytes = path.as_bytes();
    w.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
    w.write_all(path_bytes)?;
    w.write_all(&offset.to_le_bytes())?;
    w.write_all(&size.to_le_bytes())?;
    w.flush()
}

pub fn write_u8(w: &mut impl Write, v: u8) -> io::Result<()> {
    w.write_all(&[v])
}

pub fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

pub fn write_u64(w: &mut impl Write, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

pub fn read_u8(r: &mut impl Read) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

pub fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub fn read_u64(r: &mut impl Read) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

pub fn read_path(r: &mut impl Read) -> io::Result<String> {
    let len = read_u32(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// STAT response fields.
pub struct StatResponse {
    pub mode: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub nlink: u64,
    pub ino: u64,
}

impl StatResponse {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        write_u32(w, self.mode)?;
        write_u64(w, self.size)?;
        write_u32(w, self.uid)?;
        write_u32(w, self.gid)?;
        write_u64(w, self.mtime)?;
        write_u64(w, self.nlink)?;
        write_u64(w, self.ino)
    }

    pub fn read_from(r: &mut impl Read) -> io::Result<Self> {
        Ok(Self {
            mode: read_u32(r)?,
            size: read_u64(r)?,
            uid: read_u32(r)?,
            gid: read_u32(r)?,
            mtime: read_u64(r)?,
            nlink: read_u64(r)?,
            ino: read_u64(r)?,
        })
    }
}
