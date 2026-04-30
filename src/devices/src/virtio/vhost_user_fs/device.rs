//! VirtioFS device backed by external virtiofsd via vhost-user protocol.
//!
//! Unlike the built-in Fs device which runs PassthroughFs in-process, this
//! device delegates all FUSE processing to an external virtiofsd daemon
//! connected via Unix socket. The virtiofsd directly accesses the shared
//! VirtIO queues for zero-copy operation.

use std::cmp;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::{virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX};
use vm_memory::{ByteValued, GuestMemory, GuestMemoryMmap};

use crate::virtio::fs::defs;
use crate::virtio::fs::defs::uapi;
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice,
    VirtioShmRegion,
};
use crate::virtio::InterruptTransport;

use super::protocol::{VhostUserFrontend, VhostUserMemoryRegion, VhostUserVringAddr};

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; 36],
    num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; 36],
            num_request_queues: 0,
        }
    }
}

unsafe impl ByteValued for VirtioFsConfig {}

/// VirtioFS device that delegates to external virtiofsd via vhost-user.
pub struct VhostUserFs {
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    config: VirtioFsConfig,
    shm_region: Option<VirtioShmRegion>,
    socket_path: String,
    exit_code: Arc<AtomicI32>,
}

impl VhostUserFs {
    /// Create a new vhost-user-fs device.
    ///
    /// * `fs_id` - Mount tag visible in the guest
    /// * `socket_path` - Path to external virtiofsd Unix socket
    /// * `exit_code` - Shared exit code for error reporting
    pub fn new(
        fs_id: String,
        socket_path: String,
        exit_code: Arc<AtomicI32>,
    ) -> super::Result<Self> {
        let avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        let tag = fs_id.into_bytes();
        let mut config = VirtioFsConfig::default();
        let tag_len = std::cmp::min(tag.len(), 36);
        config.tag[..tag_len].copy_from_slice(&tag[..tag_len]);
        config.num_request_queues = 1;

        Ok(VhostUserFs {
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            config,
            shm_region: None,
            socket_path,
            exit_code,
        })
    }

    /// Set the SHM region for DAX support.
    pub fn set_shm_region(&mut self, shm_region: VirtioShmRegion) {
        self.shm_region = Some(shm_region);
    }
}

impl VirtioDevice for VhostUserFs {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_FS
    }

    fn device_name(&self) -> &str {
        "vhost-user-fs"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "vhost-user-fs: guest attempted to write config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        // Connect to external virtiofsd
        let frontend = VhostUserFrontend::connect(&self.socket_path).map_err(|e| {
            error!("vhost-user-fs: failed to connect to {}: {}", self.socket_path, e);
            ActivateError::BadActivate
        })?;

        // Feature negotiation
        let backend_features = frontend.get_features().map_err(|e| {
            error!("vhost-user-fs: get_features failed: {}", e);
            ActivateError::BadActivate
        })?;
        let negotiated = self.acked_features & backend_features;
        frontend.set_features(negotiated).map_err(|e| {
            error!("vhost-user-fs: set_features failed: {}", e);
            ActivateError::BadActivate
        })?;

        frontend.set_owner().map_err(|e| {
            error!("vhost-user-fs: set_owner failed: {}", e);
            ActivateError::BadActivate
        })?;

        // Share guest memory with virtiofsd
        let mut regions = Vec::new();
        let mut fds = Vec::new();
        mem.iter().for_each(|region| {
            regions.push(VhostUserMemoryRegion {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len(),
                user_addr: region.as_ptr() as u64,
                mmap_offset: 0,
            });
            // virtiofsd needs the fd to mmap the region
            // On macOS with HVF, guest memory is allocated via mmap,
            // so we can share it via /dev/zero fd as placeholder.
            // A real implementation would pass the actual memfd.
            fds.push(-1i32); // placeholder — needs real memfd
        });
        // Note: SET_MEM_TABLE with actual memory fds is complex and
        // platform-specific. This is a WIP placeholder.
        if let Err(e) = frontend.set_mem_table(&regions, &fds.iter().map(|f| *f).collect::<Vec<_>>()) {
            warn!("vhost-user-fs: set_mem_table failed: {} (expected for WIP)", e);
        }

        // Configure vrings
        for (i, dq) in queues.iter().enumerate() {
            let queue = &dq.queue;

            frontend.set_vring_num(i as u32, queue.size).map_err(|e| {
                error!("vhost-user-fs: set_vring_num failed: {}", e);
                ActivateError::BadActivate
            })?;

            frontend.set_vring_base(i as u32, 0).map_err(|e| {
                error!("vhost-user-fs: set_vring_base failed: {}", e);
                ActivateError::BadActivate
            })?;

            let addr = VhostUserVringAddr {
                index: i as u32,
                flags: 0,
                descriptor: queue.desc_table.raw_value(),
                used: queue.used_ring.raw_value(),
                available: queue.avail_ring.raw_value(),
                log: 0,
            };
            frontend.set_vring_addr(&addr).map_err(|e| {
                error!("vhost-user-fs: set_vring_addr failed: {}", e);
                ActivateError::BadActivate
            })?;

            // Kick fd: guest notifies virtiofsd that new buffers are available
            frontend
                .set_vring_kick(i as u32, dq.event.as_raw_fd())
                .map_err(|e| {
                    error!("vhost-user-fs: set_vring_kick failed: {}", e);
                    ActivateError::BadActivate
                })?;

            // Call fd: virtiofsd notifies guest that buffers have been used
            let call_fd = EventFd::new(EFD_NONBLOCK).map_err(|_| ActivateError::BadActivate)?;
            frontend
                .set_vring_call(i as u32, call_fd.as_raw_fd())
                .map_err(|e| {
                    error!("vhost-user-fs: set_vring_call failed: {}", e);
                    ActivateError::BadActivate
                })?;

            // Enable the vring
            frontend.set_vring_enable(i as u32, true).map_err(|e| {
                error!("vhost-user-fs: set_vring_enable failed: {}", e);
                ActivateError::BadActivate
            })?;
        }

        info!(
            "vhost-user-fs: activated with {} queues, connected to {}",
            queues.len(),
            self.socket_path
        );

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        self.shm_region.as_ref()
    }

    fn reset(&mut self) -> bool {
        self.device_state = DeviceState::Inactive;
        true
    }
}
