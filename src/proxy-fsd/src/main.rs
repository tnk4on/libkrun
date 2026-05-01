//! proxy-fsd: File server for ProxyFs.
//!
//! Serves files from a root directory over Unix socket, TCP, or vsock.
//! Designed to run inside a VM (e.g., podman-machine) and serve container
//! rootfs to a ProxyFs instance in another VM via vsock relay.
//!
//! Usage:
//!   proxy-fsd --root /var/lib/.../merged --socket /tmp/proxy-fsd.sock
//!   proxy-fsd --root /var/lib/.../merged --vsock-connect 5001
//!   proxy-fsd --root /var/lib/.../merged --tcp-port 5001

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use proxy_fs_proto::*;

fn handle_stat(stream: &mut (impl Read + Write), root: &Path, rel_path: &str) -> io::Result<()> {
    let full_path = root.join(rel_path.trim_start_matches('/'));
    match fs::symlink_metadata(&full_path) {
        Ok(meta) => {
            write_u8(stream, STATUS_OK)?;
            StatResponse {
                mode: meta.mode(),
                size: meta.size(),
                uid: meta.uid(),
                gid: meta.gid(),
                mtime: meta.mtime() as u64,
                nlink: meta.nlink(),
                ino: meta.ino(),
            }
            .write_to(stream)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => write_u8(stream, STATUS_ENOENT)?,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            write_u8(stream, STATUS_EACCES)?
        }
        Err(_) => write_u8(stream, STATUS_ERROR)?,
    }
    Ok(())
}

fn handle_read(stream: &mut (impl Read + Write), root: &Path, rel_path: &str) -> io::Result<()> {
    let full_path = root.join(rel_path.trim_start_matches('/'));
    match fs::read(&full_path) {
        Ok(data) => {
            write_u8(stream, STATUS_OK)?;
            write_u64(stream, data.len() as u64)?;
            stream.write_all(&data)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => write_u8(stream, STATUS_ENOENT)?,
        Err(_) => write_u8(stream, STATUS_ERROR)?,
    }
    Ok(())
}

fn handle_readdir(
    stream: &mut (impl Read + Write),
    root: &Path,
    rel_path: &str,
) -> io::Result<()> {
    let full_path = root.join(rel_path.trim_start_matches('/'));
    match fs::read_dir(&full_path) {
        Ok(entries) => {
            let mut names: Vec<(String, u32)> = Vec::new();
            for entry in entries.flatten() {
                let file_type = entry
                    .file_type()
                    .map(|ft| {
                        if ft.is_dir() {
                            S_IFDIR
                        } else if ft.is_symlink() {
                            S_IFLNK
                        } else {
                            S_IFREG
                        }
                    })
                    .unwrap_or(S_IFREG);
                names.push((entry.file_name().to_string_lossy().into_owned(), file_type));
            }
            write_u8(stream, STATUS_OK)?;
            write_u32(stream, names.len() as u32)?;
            for (name, ftype) in &names {
                write_u32(stream, name.len() as u32)?;
                stream.write_all(name.as_bytes())?;
                write_u32(stream, *ftype)?;
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => write_u8(stream, STATUS_ENOENT)?,
        Err(_) => write_u8(stream, STATUS_ERROR)?,
    }
    Ok(())
}

fn handle_read_range(
    stream: &mut (impl Read + Write),
    root: &Path,
    rel_path: &str,
    offset: u64,
    size: u32,
) -> io::Result<()> {
    let full_path = root.join(rel_path.trim_start_matches('/'));
    match std::fs::File::open(&full_path) {
        Ok(mut file) => {
            use std::io::Seek;
            let file_len = file.seek(io::SeekFrom::End(0))?;
            if offset >= file_len {
                write_u8(stream, STATUS_OK)?;
                write_u32(stream, 0)?;
                return Ok(());
            }
            file.seek(io::SeekFrom::Start(offset))?;
            let remaining = (file_len - offset) as usize;
            let to_read = std::cmp::min(size as usize, remaining);
            let mut buf = vec![0u8; to_read];
            let mut total = 0;
            while total < to_read {
                match file.read(&mut buf[total..]) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            write_u8(stream, STATUS_OK)?;
            write_u32(stream, total as u32)?;
            stream.write_all(&buf[..total])?;
            stream.flush()?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => write_u8(stream, STATUS_ENOENT)?,
        Err(_) => write_u8(stream, STATUS_ERROR)?,
    }
    Ok(())
}

fn handle_readlink(
    stream: &mut (impl Read + Write),
    root: &Path,
    rel_path: &str,
) -> io::Result<()> {
    let full_path = root.join(rel_path.trim_start_matches('/'));
    match fs::read_link(&full_path) {
        Ok(target) => {
            let target_str = target.to_string_lossy().into_owned();
            write_u8(stream, STATUS_OK)?;
            write_u32(stream, target_str.len() as u32)?;
            stream.write_all(target_str.as_bytes())?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => write_u8(stream, STATUS_ENOENT)?,
        Err(_) => write_u8(stream, STATUS_ERROR)?,
    }
    Ok(())
}

fn handle_client(mut stream: impl Read + Write, root: &Path) {
    eprintln!("proxy-fsd: client connected");
    loop {
        let op = match read_u8(&mut stream) {
            Ok(op) => op,
            Err(_) => break,
        };
        let path = match read_path(&mut stream) {
            Ok(p) => p,
            Err(_) => break,
        };
        let result = match op {
            OP_STAT => handle_stat(&mut stream, root, &path),
            OP_READ => handle_read(&mut stream, root, &path),
            OP_READDIR => handle_readdir(&mut stream, root, &path),
            OP_READLINK => handle_readlink(&mut stream, root, &path),
            OP_READ_RANGE => {
                let offset = match read_u64(&mut stream) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let size = match read_u32(&mut stream) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                handle_read_range(&mut stream, root, &path, offset, size)
            }
            _ => {
                let _ = write_u8(&mut stream, STATUS_ERROR);
                continue;
            }
        };
        if let Err(e) = result {
            eprintln!("proxy-fsd: error handling op {}: {}", op, e);
            break;
        }
    }
    eprintln!("proxy-fsd: client disconnected");
}

fn run_unix(root: &Path, socket_path: &str) -> io::Result<()> {
    eprintln!("proxy-fsd: serving {} on {}", root.display(), socket_path);
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let root = root.to_path_buf();
                std::thread::spawn(move || handle_client(stream, &root));
            }
            Err(e) => eprintln!("proxy-fsd: accept error: {}", e),
        }
    }
    Ok(())
}

fn run_tcp(root: &Path, port: u16) -> io::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    eprintln!("proxy-fsd: serving {} on tcp://{}", root.display(), addr);
    let listener = TcpListener::bind(&addr)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let root = root.to_path_buf();
                std::thread::spawn(move || handle_client(stream, &root));
            }
            Err(e) => eprintln!("proxy-fsd: accept error: {}", e),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_vsock_connect(root: &Path, port: u32) -> io::Result<()> {
    use vsock::VsockStream;
    eprintln!(
        "proxy-fsd: connecting to host vsock CID=2 port {} to serve {}",
        port,
        root.display()
    );
    let stream = loop {
        match VsockStream::connect_with_cid_port(2, port) {
            Ok(s) => break s,
            Err(e) => {
                eprintln!("proxy-fsd: vsock connect retry ({})", e);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    };
    eprintln!("proxy-fsd: connected to host via vsock");
    handle_client(stream, root);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut root = PathBuf::from("/");
    let mut socket_path: Option<String> = None;
    let mut tcp_port: Option<u16> = None;
    let mut vsock_connect: Option<u32> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                i += 1;
                root = PathBuf::from(&args[i]);
            }
            "--socket" => {
                i += 1;
                socket_path = Some(args[i].clone());
            }
            "--tcp-port" => {
                i += 1;
                tcp_port = Some(args[i].parse().expect("invalid tcp port"));
            }
            "--vsock-connect" => {
                i += 1;
                vsock_connect = Some(args[i].parse().expect("invalid vsock port"));
            }
            _ => {
                eprintln!("Unknown arg: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let result = if let Some(port) = vsock_connect {
        #[cfg(target_os = "linux")]
        {
            run_vsock_connect(&root, port)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = port;
            eprintln!("vsock is only supported on Linux");
            std::process::exit(1);
        }
    } else if let Some(port) = tcp_port {
        run_tcp(&root, port)
    } else {
        let sock = socket_path.unwrap_or_else(|| "/tmp/proxy-fsd.sock".to_string());
        run_unix(&root, &sock)
    };

    if let Err(e) = result {
        eprintln!("proxy-fsd: fatal error: {}", e);
        std::process::exit(1);
    }
}
