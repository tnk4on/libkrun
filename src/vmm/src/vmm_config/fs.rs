#[derive(Clone, Debug)]
pub struct FsDeviceConfig {
    pub fs_id: String,
    pub shared_dir: String,
    pub shm_size: Option<usize>,
    pub allow_root_dir_delete: bool,
    pub read_only: bool,
    /// Path to external virtiofsd Unix socket (vhost-user mode).
    /// When set, delegates FUSE processing to external virtiofsd
    /// instead of using built-in PassthroughFs.
    pub socket_path: Option<String>,
}
