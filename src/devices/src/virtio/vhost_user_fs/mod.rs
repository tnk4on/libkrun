//! VirtioFS device backed by an external virtiofsd via vhost-user protocol.
//!
//! This module implements a minimal vhost-user frontend that connects to
//! an external virtiofsd process via Unix socket. The virtiofsd handles
//! FUSE requests directly from the shared VirtIO queues, enabling
//! zero-copy filesystem sharing.
//!
//! The vhost-user protocol implementation is self-contained (no vhost crate
//! dependency) to support macOS where eventfd is not available.

mod protocol;

pub use protocol::VhostUserFrontend;
