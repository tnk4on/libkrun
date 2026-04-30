//! Minimal vhost-user protocol implementation for macOS compatibility.
//!
//! Implements the subset of vhost-user protocol needed for virtio-fs:
//! - Unix socket connection with SCM_RIGHTS (fd passing)
//! - Feature negotiation
//! - Memory table sharing
//! - Vring configuration and activation
//!
//! This avoids depending on the `vhost` crate which requires Linux eventfd.

use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

// ============================================================================
// vhost-user message types (subset needed for virtio-fs)
// ============================================================================

/// vhost-user request types (frontend → backend)
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum FrontendReq {
    GetFeatures = 1,
    SetFeatures = 2,
    SetOwner = 3,
    SetMemTable = 5,
    SetVringNum = 8,
    SetVringAddr = 9,
    SetVringBase = 10,
    GetVringBase = 11,
    SetVringKick = 12,
    SetVringCall = 13,
    SetVringErr = 14,
    GetProtocolFeatures = 15,
    SetProtocolFeatures = 16,
    GetQueueNum = 17,
    SetVringEnable = 18,
}

/// vhost-user message header (12 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct VhostUserMsgHeader {
    request: u32,
    flags: u32,
    size: u32,
}

const VHOST_USER_HEADER_SIZE: usize = mem::size_of::<VhostUserMsgHeader>();
const VHOST_USER_VERSION: u32 = 0x1;
const VHOST_USER_REPLY_MASK: u32 = 0x4;

/// vhost-user memory region (32 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct VhostUserMemoryRegion {
    /// Guest physical address
    pub guest_phys_addr: u64,
    /// Region size
    pub memory_size: u64,
    /// User-space address (host virtual)
    pub user_addr: u64,
    /// mmap offset
    pub mmap_offset: u64,
}

/// vhost-user memory table header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct VhostUserMemory {
    num_regions: u32,
    padding: u32,
}

/// vhost-user vring state (index + value)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct VhostUserVringState {
    index: u32,
    num: u32,
}

/// vhost-user vring address
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct VhostUserVringAddr {
    /// Vring index
    pub index: u32,
    /// Flags
    pub flags: u32,
    /// Descriptor table address
    pub descriptor: u64,
    /// Used ring address
    pub used: u64,
    /// Available ring address
    pub available: u64,
    /// Log address (unused for virtio-fs)
    pub log: u64,
}

// ============================================================================
// Unix socket with SCM_RIGHTS (fd passing) — works on macOS
// ============================================================================

/// Send bytes with optional file descriptors over Unix socket
fn send_with_fds(sock: &UnixStream, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    use libc::{c_void, cmsghdr, iovec, msghdr, sendmsg, CMSG_DATA, CMSG_LEN, CMSG_SPACE, SOL_SOCKET, SCM_RIGHTS};

    let iov = iovec {
        iov_base: data.as_ptr() as *mut c_void,
        iov_len: data.len(),
    };

    if fds.is_empty() {
        let msg = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &iov as *const _ as *mut _,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let ret = unsafe { sendmsg(sock.as_raw_fd(), &msg, 0) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(());
    }

    let cmsg_len = unsafe { CMSG_SPACE(mem::size_of_val(fds) as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_len];

    let mut msg = msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &iov as *const _ as *mut _,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut c_void,
        msg_controllen: cmsg_len as _,
        msg_flags: 0,
    };

    unsafe {
        let cmsg: *mut cmsghdr = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = SOL_SOCKET;
        (*cmsg).cmsg_type = SCM_RIGHTS;
        (*cmsg).cmsg_len = CMSG_LEN(mem::size_of_val(fds) as u32) as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr(),
            CMSG_DATA(cmsg) as *mut RawFd,
            fds.len(),
        );

        let ret = sendmsg(sock.as_raw_fd(), &msg, 0);
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Receive bytes with optional file descriptors from Unix socket
fn recv_with_fds(sock: &UnixStream, buf: &mut [u8], max_fds: usize) -> io::Result<(usize, Vec<RawFd>)> {
    use libc::{c_void, cmsghdr, iovec, msghdr, recvmsg, CMSG_DATA, CMSG_SPACE, SOL_SOCKET, SCM_RIGHTS};

    let iov = iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: buf.len(),
    };

    let cmsg_len = unsafe { CMSG_SPACE((max_fds * mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_len];

    let mut msg = msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &iov as *const _ as *mut _,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut c_void,
        msg_controllen: cmsg_len as _,
        msg_flags: 0,
    };

    let n = unsafe { recvmsg(sock.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut fds = Vec::new();
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == SOL_SOCKET && (*cmsg).cmsg_type == SCM_RIGHTS {
                let fd_count = ((*cmsg).cmsg_len as usize - mem::size_of::<cmsghdr>())
                    / mem::size_of::<RawFd>();
                let fd_ptr = CMSG_DATA(cmsg) as *const RawFd;
                for i in 0..fd_count {
                    fds.push(*fd_ptr.add(i));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((n as usize, fds))
}

// ============================================================================
// VhostUserFrontend — minimal vhost-user client
// ============================================================================

/// Minimal vhost-user frontend for connecting to external virtiofsd.
///
/// Implements only the subset of vhost-user protocol needed for virtio-fs
/// without depending on the `vhost` crate (which requires Linux eventfd).
pub struct VhostUserFrontend {
    sock: UnixStream,
}

impl VhostUserFrontend {
    /// Connect to an external virtiofsd via Unix socket.
    pub fn connect(path: &str) -> io::Result<Self> {
        let sock = UnixStream::connect(path)?;
        Ok(Self { sock })
    }

    /// Send a request with no payload.
    fn send_request(&self, req: FrontendReq) -> io::Result<()> {
        let hdr = VhostUserMsgHeader {
            request: req as u32,
            flags: VHOST_USER_VERSION,
            size: 0,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &hdr as *const _ as *const u8,
                VHOST_USER_HEADER_SIZE,
            )
        };
        send_with_fds(&self.sock, bytes, &[])?;
        Ok(())
    }

    /// Send a request with payload.
    fn send_request_with_payload<T>(&self, req: FrontendReq, payload: &T) -> io::Result<()> {
        let payload_size = mem::size_of::<T>();
        let hdr = VhostUserMsgHeader {
            request: req as u32,
            flags: VHOST_USER_VERSION,
            size: payload_size as u32,
        };

        let mut buf = Vec::with_capacity(VHOST_USER_HEADER_SIZE + payload_size);
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, VHOST_USER_HEADER_SIZE)
        });
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(payload as *const _ as *const u8, payload_size)
        });

        send_with_fds(&self.sock, &buf, &[])?;
        Ok(())
    }

    /// Send a request with a file descriptor.
    fn send_request_with_fd(&self, req: FrontendReq, payload: &VhostUserVringState, fd: RawFd) -> io::Result<()> {
        let payload_size = mem::size_of::<VhostUserVringState>();
        let hdr = VhostUserMsgHeader {
            request: req as u32,
            flags: VHOST_USER_VERSION,
            size: payload_size as u32,
        };

        let mut buf = Vec::with_capacity(VHOST_USER_HEADER_SIZE + payload_size);
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, VHOST_USER_HEADER_SIZE)
        });
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(payload as *const _ as *const u8, payload_size)
        });

        send_with_fds(&self.sock, &buf, &[fd])?;
        Ok(())
    }

    /// Receive a reply (header + u64 value).
    fn recv_reply_u64(&self) -> io::Result<u64> {
        let mut buf = [0u8; VHOST_USER_HEADER_SIZE + 8];
        let (n, _) = recv_with_fds(&self.sock, &mut buf, 0)?;
        if n < VHOST_USER_HEADER_SIZE + 8 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short reply"));
        }
        let val = u64::from_le_bytes(buf[VHOST_USER_HEADER_SIZE..].try_into().unwrap());
        Ok(val)
    }

    /// Receive an ack reply (header only, no payload).
    fn recv_ack(&self) -> io::Result<()> {
        let mut buf = [0u8; VHOST_USER_HEADER_SIZE + 8];
        let _ = recv_with_fds(&self.sock, &mut buf, 0)?;
        Ok(())
    }

    // ========================================================================
    // Public vhost-user operations
    // ========================================================================

    /// Get virtio features from the backend.
    pub fn get_features(&self) -> io::Result<u64> {
        self.send_request(FrontendReq::GetFeatures)?;
        self.recv_reply_u64()
    }

    /// Set virtio features.
    pub fn set_features(&self, features: u64) -> io::Result<()> {
        let hdr = VhostUserMsgHeader {
            request: FrontendReq::SetFeatures as u32,
            flags: VHOST_USER_VERSION,
            size: 8,
        };
        let mut buf = Vec::with_capacity(VHOST_USER_HEADER_SIZE + 8);
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, VHOST_USER_HEADER_SIZE)
        });
        buf.extend_from_slice(&features.to_le_bytes());
        send_with_fds(&self.sock, &buf, &[])
    }

    /// Claim ownership of the backend.
    pub fn set_owner(&self) -> io::Result<()> {
        self.send_request(FrontendReq::SetOwner)
    }

    /// Get protocol features.
    pub fn get_protocol_features(&self) -> io::Result<u64> {
        self.send_request(FrontendReq::GetProtocolFeatures)?;
        self.recv_reply_u64()
    }

    /// Set protocol features.
    pub fn set_protocol_features(&self, features: u64) -> io::Result<()> {
        let hdr = VhostUserMsgHeader {
            request: FrontendReq::SetProtocolFeatures as u32,
            flags: VHOST_USER_VERSION,
            size: 8,
        };
        let mut buf = Vec::with_capacity(VHOST_USER_HEADER_SIZE + 8);
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, VHOST_USER_HEADER_SIZE)
        });
        buf.extend_from_slice(&features.to_le_bytes());
        send_with_fds(&self.sock, &buf, &[])
    }

    /// Set memory table — share guest memory regions with virtiofsd.
    pub fn set_mem_table(&self, regions: &[VhostUserMemoryRegion], fds: &[RawFd]) -> io::Result<()> {
        let mem_hdr = VhostUserMemory {
            num_regions: regions.len() as u32,
            padding: 0,
        };
        let mem_hdr_size = mem::size_of::<VhostUserMemory>();
        let regions_size = regions.len() * mem::size_of::<VhostUserMemoryRegion>();
        let payload_size = mem_hdr_size + regions_size;

        let hdr = VhostUserMsgHeader {
            request: FrontendReq::SetMemTable as u32,
            flags: VHOST_USER_VERSION,
            size: payload_size as u32,
        };

        let mut buf = Vec::with_capacity(VHOST_USER_HEADER_SIZE + payload_size);
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, VHOST_USER_HEADER_SIZE)
        });
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&mem_hdr as *const _ as *const u8, mem_hdr_size)
        });
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(regions.as_ptr() as *const u8, regions_size)
        });

        send_with_fds(&self.sock, &buf, fds)
    }

    /// Set vring size.
    pub fn set_vring_num(&self, index: u32, num: u32) -> io::Result<()> {
        let state = VhostUserVringState { index, num };
        self.send_request_with_payload(FrontendReq::SetVringNum, &state)
    }

    /// Set vring addresses (descriptor, used, available rings).
    pub fn set_vring_addr(&self, addr: &VhostUserVringAddr) -> io::Result<()> {
        self.send_request_with_payload(FrontendReq::SetVringAddr, addr)
    }

    /// Set vring base index.
    pub fn set_vring_base(&self, index: u32, base: u32) -> io::Result<()> {
        let state = VhostUserVringState { index, num: base };
        self.send_request_with_payload(FrontendReq::SetVringBase, &state)
    }

    /// Set vring kick fd (guest → virtiofsd notification).
    pub fn set_vring_kick(&self, index: u32, fd: RawFd) -> io::Result<()> {
        let state = VhostUserVringState { index, num: 0 };
        self.send_request_with_fd(FrontendReq::SetVringKick, &state, fd)
    }

    /// Set vring call fd (virtiofsd → guest notification).
    pub fn set_vring_call(&self, index: u32, fd: RawFd) -> io::Result<()> {
        let state = VhostUserVringState { index, num: 0 };
        self.send_request_with_fd(FrontendReq::SetVringCall, &state, fd)
    }

    /// Enable or disable a vring.
    pub fn set_vring_enable(&self, index: u32, enable: bool) -> io::Result<()> {
        let state = VhostUserVringState {
            index,
            num: if enable { 1 } else { 0 },
        };
        self.send_request_with_payload(FrontendReq::SetVringEnable, &state)
    }

    /// Get the number of supported queues.
    pub fn get_queue_num(&self) -> io::Result<u64> {
        self.send_request(FrontendReq::GetQueueNum)?;
        self.recv_reply_u64()
    }
}
