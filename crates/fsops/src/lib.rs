//! Native E3 file operations using Linux `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`),
//! `renameat2(RENAME_NOREPLACE)`, 4 GB / 30-day Undo backup store, and conflict-checked ChangeSet undo (§8.5, §9).

use chrono::{Duration, Utc};
use intentos_protocol::{ChangeOp, ChangeSet, ChangeSetStatus, FileIdentity};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub const DEFAULT_BACKUP_QUOTA_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB
pub const DEFAULT_RETENTION_DAYS: i64 = 30;

// Linux openat2 resolve flags (uapi/linux/openat2.h)
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

// ioctl FICLONE for copy-on-write reflink on Btrfs/XFS
const FICLONE: libc::c_ulong = 0x4004_9409;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Debug, Error)]
pub enum FsOpsError {
    #[error("path is outside authorized directories: {0}")]
    OutsideAuthorizedScope(String),
    #[error("access to forbidden path is strictly denied: {0}")]
    ForbiddenPath(String),
    #[error("path traversal or symlink escape blocked by openat2: {0}")]
    EscapeBlocked(String),
    #[error("target already exists (RENAME_NOREPLACE): {0}")]
    TargetAlreadyExists(String),
    #[error(
        "backup quota exceeded (needed {needed} bytes, max single/remaining {limit} bytes); upgrade to write.destructive"
    )]
    BackupQuotaExceeded { needed: u64, limit: u64 },
    #[error("changeset cannot be undone (status: {0:?})")]
    NotUndoable(ChangeSetStatus),
    #[error("undo expired at {0}")]
    UndoExpired(String),
    #[error("invalid path argument: {0}")]
    InvalidPath(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct UndoOutcome {
    pub changeset_id: String,
    pub restored_ops: usize,
    pub conflicts: Vec<String>,
}

/// 4-tier path sensitivity classification for user-space visibility & interactive approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSensitivity {
    Forbidden,
    NormalUserSpace,
    SensitiveDotPath,
    OutsideScope,
}

fn has_dot_normal_component(path: &Path, skip_tmp_tempdir_root: bool) -> bool {
    let under_tmp = skip_tmp_tempdir_root && path.starts_with("/tmp");
    let mut normal_idx = 0usize;
    for comp in path.components() {
        if let Component::Normal(seg) = comp {
            let s = seg.to_string_lossy();
            let is_tempdir_bucket = under_tmp && normal_idx == 1 && s.starts_with(".tmp");
            normal_idx += 1;
            if is_tempdir_bucket {
                continue;
            }
            if s.starts_with('.') {
                return true;
            }
        }
    }
    false
}

/// Manages authorized directory boundaries, dynamically approved roots, forbidden path rules, and the Undo backup area.
#[derive(Debug, Clone)]
pub struct SafeFsEngine {
    authorized_roots: Vec<PathBuf>,
    approved_roots: Arc<Mutex<Vec<PathBuf>>>,
    forbidden_prefixes: Vec<PathBuf>,
    backup_dir: PathBuf,
    trash_dir: PathBuf,
    quota_bytes: u64,
    retention_days: i64,
}

impl SafeFsEngine {
    pub fn new(
        authorized_roots: Vec<PathBuf>,
        forbidden_prefixes: Vec<PathBuf>,
        backup_dir: PathBuf,
        trash_dir: PathBuf,
    ) -> Result<Self, FsOpsError> {
        fs::create_dir_all(&backup_dir)?;
        fs::create_dir_all(trash_dir.join("files"))?;
        fs::create_dir_all(trash_dir.join("info"))?;
        Ok(Self {
            authorized_roots,
            approved_roots: Arc::new(Mutex::new(Vec::new())),
            forbidden_prefixes,
            backup_dir,
            trash_dir,
            quota_bytes: DEFAULT_BACKUP_QUOTA_BYTES,
            retention_days: DEFAULT_RETENTION_DAYS,
        })
    }

    pub fn with_quota(mut self, quota_bytes: u64, retention_days: i64) -> Self {
        self.quota_bytes = quota_bytes;
        self.retention_days = retention_days;
        self
    }

    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    pub fn authorized_roots(&self) -> &[PathBuf] {
        &self.authorized_roots
    }

    /// Approve a user-confirmed path scope for `openat2`-confined operations during the current runtime.
    pub fn approve_path_scope(&self, target: &Path) -> Result<PathBuf, FsOpsError> {
        if self.is_forbidden(target) {
            return Err(FsOpsError::ForbiddenPath(target.display().to_string()));
        }
        for comp in target.components() {
            if matches!(comp, Component::ParentDir) {
                return Err(FsOpsError::EscapeBlocked(format!(
                    "parent traversal '..' rejected in {}",
                    target.display()
                )));
            }
        }
        let scope = if target.is_dir() {
            target.to_path_buf()
        } else {
            target.parent().unwrap_or(target).to_path_buf()
        };
        if self.is_forbidden(&scope) {
            return Err(FsOpsError::ForbiddenPath(scope.display().to_string()));
        }
        let mut guard = self.approved_roots.lock().unwrap();
        if !guard.iter().any(|r| r == &scope) {
            guard.push(scope.clone());
        }
        Ok(scope)
    }

    pub fn list_approved_roots(&self) -> Vec<PathBuf> {
        self.approved_roots.lock().unwrap().clone()
    }

    pub fn revoke_approved_root(&self, root: &Path) -> bool {
        let mut guard = self.approved_roots.lock().unwrap();
        let before = guard.len();
        guard.retain(|r| r != root);
        guard.len() < before
    }

    /// Built-in forbidden path detector (§5.4, §10.7).
    pub fn is_forbidden(&self, candidate: &Path) -> bool {
        let raw = candidate.to_string_lossy();
        let forbidden_names = [
            "/.ssh",
            "/.gnupg",
            "/.aws",
            "/.kube",
            "/.docker/config.json",
            "/.netrc",
            "/.git-credentials",
            "/keyrings",
            "/.local/share/keyrings",
            "/.config/intentos",
            "/.local/share/intentos",
            "/.local/state/intentos",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/sudoers",
        ];
        for marker in forbidden_names {
            if raw.contains(marker) || raw.ends_with(marker) {
                return true;
            }
        }
        if candidate.starts_with("/etc/shadow")
            || candidate.starts_with("/etc/gshadow")
            || candidate.starts_with("/etc/sudoers")
        {
            return true;
        }
        for comp in candidate.components() {
            if let Component::Normal(seg) = comp
                && let Some(s) = seg.to_str()
                && matches!(
                    s,
                    ".ssh"
                        | ".gnupg"
                        | ".aws"
                        | ".kube"
                        | ".netrc"
                        | ".git-credentials"
                        | "keyrings"
                )
            {
                return true;
            }
        }
        if let Some(file_name) = candidate.file_name().and_then(|n| n.to_str())
            && matches!(
                file_name,
                "id_rsa" | "id_ed25519" | "Cookies" | "Login Data"
            )
        {
            return true;
        }
        for prefix in &self.forbidden_prefixes {
            if candidate.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    /// Classify a candidate path across the 4 sensitivity tiers.
    pub fn classify_path_sensitivity(&self, candidate: &Path) -> PathSensitivity {
        if self.is_forbidden(candidate) {
            return PathSensitivity::Forbidden;
        }

        {
            let approved = self.approved_roots.lock().unwrap();
            if approved.iter().any(|root| candidate.starts_with(root)) {
                return PathSensitivity::NormalUserSpace;
            }
        }

        let mut best_auth_root: Option<&Path> = None;
        for root in &self.authorized_roots {
            if candidate.starts_with(root) {
                match best_auth_root {
                    None => best_auth_root = Some(root.as_path()),
                    Some(prev) if root.as_os_str().len() > prev.as_os_str().len() => {
                        best_auth_root = Some(root.as_path());
                    }
                    _ => {}
                }
            }
        }

        if let Some(auth_root) = best_auth_root {
            if let Ok(rel) = candidate.strip_prefix(auth_root)
                && has_dot_normal_component(rel, false)
            {
                return PathSensitivity::SensitiveDotPath;
            }
            return PathSensitivity::NormalUserSpace;
        }

        if has_dot_normal_component(candidate, true) {
            return PathSensitivity::SensitiveDotPath;
        }

        PathSensitivity::OutsideScope
    }

    /// Match a path to an authorized or user-approved root without following symlinks in the relative suffix.
    fn split_authorized_root(&self, target: &Path) -> Result<(PathBuf, PathBuf), FsOpsError> {
        if !target.is_absolute() {
            return Err(FsOpsError::InvalidPath(format!(
                "path must be absolute: {}",
                target.display()
            )));
        }
        if self.is_forbidden(target) {
            return Err(FsOpsError::ForbiddenPath(target.display().to_string()));
        }

        // Reject lexical `..` before even calling the kernel (defense in depth; openat2 also blocks it).
        for comp in target.components() {
            if matches!(comp, Component::ParentDir) {
                return Err(FsOpsError::EscapeBlocked(format!(
                    "parent traversal '..' rejected in {}",
                    target.display()
                )));
            }
        }

        let mut best_root: Option<PathBuf> = None;
        for root in &self.authorized_roots {
            if target.starts_with(root) {
                match &best_root {
                    None => best_root = Some(root.clone()),
                    Some(prev) if root.as_os_str().len() > prev.as_os_str().len() => {
                        best_root = Some(root.clone());
                    }
                    _ => {}
                }
            }
        }
        {
            let approved = self.approved_roots.lock().unwrap();
            for root in approved.iter() {
                if target.starts_with(root) {
                    match &best_root {
                        None => best_root = Some(root.clone()),
                        Some(prev) if root.as_os_str().len() > prev.as_os_str().len() => {
                            best_root = Some(root.clone());
                        }
                        _ => {}
                    }
                }
            }
        }

        let root = best_root
            .ok_or_else(|| FsOpsError::OutsideAuthorizedScope(target.display().to_string()))?;
        let rel = target
            .strip_prefix(&root)
            .map_err(|_| FsOpsError::OutsideAuthorizedScope(target.display().to_string()))?
            .to_path_buf();
        Ok((root, rel))
    }

    /// Open an authorized root directory safely with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
    fn open_root_dirfd(&self, root: &Path) -> Result<OwnedFd, FsOpsError> {
        let c_root = CString::new(root.as_os_str().as_bytes())
            .map_err(|_| FsOpsError::InvalidPath(root.display().to_string()))?;
        // SAFETY: `c_root` is a valid NUL-terminated path string; flags open a directory fd without following symlinks.
        let fd = unsafe {
            libc::open(
                c_root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ELOOP) {
                return Err(FsOpsError::EscapeBlocked(format!(
                    "symlink root rejected: {} ({})",
                    root.display(),
                    err
                )));
            }
            return Err(FsOpsError::Io(err));
        }
        // SAFETY: `fd` was just returned >= 0 from `libc::open`.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Invoke Linux `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
    fn openat2_beneath(
        &self,
        dirfd: &OwnedFd,
        rel_path: &Path,
        flags: u64,
        mode: u64,
    ) -> Result<OwnedFd, FsOpsError> {
        let rel_bytes = if rel_path.as_os_str().is_empty() {
            b".".as_slice()
        } else {
            rel_path.as_os_str().as_bytes()
        };
        let c_rel = CString::new(rel_bytes)
            .map_err(|_| FsOpsError::InvalidPath(rel_path.display().to_string()))?;
        let how = OpenHow {
            flags: flags | (libc::O_CLOEXEC as u64),
            mode,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: `SYS_openat2` takes (dirfd, pathname, &open_how, sizeof(open_how)).
        // Kernel checks bounds, symlink resolution, and returns a new file descriptor on >= 0.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd.as_raw_fd(),
                c_rel.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EXDEV) | Some(libc::ELOOP)) {
                return Err(FsOpsError::EscapeBlocked(format!(
                    "{} ({})",
                    rel_path.display(),
                    err
                )));
            }
            return Err(FsOpsError::Io(err));
        }
        // SAFETY: `fd` >= 0 is a fresh owned file descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    /// Ensure parent directories exist strictly inside an authorized root using `mkdirat` + `openat2`.
    fn ensure_parent_dirfd(&self, full_target: &Path) -> Result<(OwnedFd, CString), FsOpsError> {
        let (root, rel) = self.split_authorized_root(full_target)?;
        let file_name = rel
            .file_name()
            .ok_or_else(|| FsOpsError::InvalidPath(full_target.display().to_string()))?;
        if file_name == "." || file_name == ".." {
            return Err(FsOpsError::InvalidPath(full_target.display().to_string()));
        }
        let c_leaf = CString::new(file_name.as_bytes())
            .map_err(|_| FsOpsError::InvalidPath(full_target.display().to_string()))?;

        if !root.exists()
            && !root.is_symlink()
            && self.list_approved_roots().iter().any(|r| r == &root)
        {
            fs::create_dir_all(&root)?;
        }
        let root_fd = self.open_root_dirfd(&root)?;
        let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
        if parent_rel.as_os_str().is_empty() {
            return Ok((root_fd, c_leaf));
        }

        // Walk components one by one, creating missing directories safely via mkdirat + openat2.
        let mut current_rel = PathBuf::new();
        for comp in parent_rel.components() {
            match comp {
                Component::Normal(seg) => {
                    current_rel.push(seg);
                    match self.openat2_beneath(
                        &root_fd,
                        &current_rel,
                        (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                        0,
                    ) {
                        Ok(_existing) => {}
                        Err(FsOpsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                            let parent_of_cur =
                                current_rel.parent().unwrap_or_else(|| Path::new(""));
                            let pfd = self.openat2_beneath(
                                &root_fd,
                                parent_of_cur,
                                (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
                                0,
                            )?;
                            let c_seg = CString::new(seg.as_bytes()).map_err(|_| {
                                FsOpsError::InvalidPath(current_rel.display().to_string())
                            })?;
                            // SAFETY: `pfd` is a valid directory fd and `c_seg` is a single normal path segment.
                            let rc =
                                unsafe { libc::mkdirat(pfd.as_raw_fd(), c_seg.as_ptr(), 0o755) };
                            if rc < 0 {
                                let mk_err = std::io::Error::last_os_error();
                                if mk_err.kind() != std::io::ErrorKind::AlreadyExists {
                                    return Err(FsOpsError::Io(mk_err));
                                }
                            }
                        }
                        Err(other) => return Err(other),
                    }
                }
                _ => {
                    return Err(FsOpsError::EscapeBlocked(format!(
                        "disallowed component in {}",
                        full_target.display()
                    )));
                }
            }
        }

        let parent_fd = self.openat2_beneath(
            &root_fd,
            parent_rel,
            (libc::O_RDONLY | libc::O_DIRECTORY) as u64,
            0,
        )?;
        Ok((parent_fd, c_leaf))
    }

    /// Open a regular file for reading strictly inside authorized scope via `openat2`.
    pub fn open_readonly_safe(&self, path: &Path) -> Result<File, FsOpsError> {
        let (root, rel) = self.split_authorized_root(path)?;
        if rel.as_os_str().is_empty() {
            return Err(FsOpsError::InvalidPath(path.display().to_string()));
        }
        let root_fd = self.open_root_dirfd(&root)?;
        let fd = self.openat2_beneath(&root_fd, &rel, libc::O_RDONLY as u64, 0)?;
        Ok(File::from(fd))
    }

    /// Compute SHA-256 and `(dev, ino)` of an authorized file via `openat2`.
    pub fn hash_and_identity(
        &self,
        path: &Path,
    ) -> Result<(String, FileIdentity, u64), FsOpsError> {
        let mut file = self.open_readonly_safe(path)?;
        let meta = file.metadata()?;
        let id = FileIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        };
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok((
            format!("sha256:{}", hex::encode(hasher.finalize())),
            id,
            meta.len(),
        ))
    }

    /// Verify leaf entry is not a symlink using `fstatat(AT_SYMLINK_NOFOLLOW)`.
    fn ensure_leaf_not_symlink(
        parent_fd: &OwnedFd,
        leaf: &CString,
        display: &Path,
    ) -> Result<(), FsOpsError> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `parent_fd` is valid, `leaf` is NUL-terminated, `st` is valid writable stat struct.
        let rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                leaf.as_ptr(),
                &mut st as *mut libc::stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc < 0 {
            return Err(FsOpsError::Io(std::io::Error::last_os_error()));
        }
        if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            return Err(FsOpsError::EscapeBlocked(format!(
                "symlink leaf rejected: {}",
                display.display()
            )));
        }
        Ok(())
    }

    /// E3 Native Move (`openat2` + `renameat2(RENAME_NOREPLACE)` + cross-FS copy-verify-delete) (§8.5).
    pub fn move_file(
        &self,
        task_id: &str,
        source: &Path,
        dest: &Path,
    ) -> Result<ChangeSet, FsOpsError> {
        let (src_parent_fd, src_leaf) = self.ensure_parent_dirfd(source)?;
        Self::ensure_leaf_not_symlink(&src_parent_fd, &src_leaf, source)?;
        let (pre_hash, _pre_id, _len) = self.hash_and_identity(source)?;

        let (dst_parent_fd, dst_leaf) = self.ensure_parent_dirfd(dest)?;

        // Try atomic same-filesystem renameat2 with RENAME_NOREPLACE.
        // SAFETY: Both dirfds and CStrings are valid; RENAME_NOREPLACE prevents silent clobbering.
        let rc = unsafe {
            libc::renameat2(
                src_parent_fd.as_raw_fd(),
                src_leaf.as_ptr(),
                dst_parent_fd.as_raw_fd(),
                dst_leaf.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };

        if rc < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EEXIST) => {
                    return Err(FsOpsError::TargetAlreadyExists(dest.display().to_string()));
                }
                Some(libc::EXDEV) => {
                    // Cross-filesystem move: copy -> verify sha256 -> unlink source.
                    self.copy_fd_verified(
                        &src_parent_fd,
                        &src_leaf,
                        &dst_parent_fd,
                        &dst_leaf,
                        &pre_hash,
                    )?;
                    // SAFETY: `src_parent_fd` and `src_leaf` are valid.
                    let ul =
                        unsafe { libc::unlinkat(src_parent_fd.as_raw_fd(), src_leaf.as_ptr(), 0) };
                    if ul < 0 {
                        // Rollback copied destination if source unlink failed.
                        unsafe {
                            libc::unlinkat(dst_parent_fd.as_raw_fd(), dst_leaf.as_ptr(), 0);
                        }
                        return Err(FsOpsError::Io(std::io::Error::last_os_error()));
                    }
                }
                _ => return Err(FsOpsError::Io(err)),
            }
        }

        // Postcondition verification: destination exists with identical hash and source is absent!
        let (post_hash, post_id, _) = self.hash_and_identity(dest)?;
        if post_hash != pre_hash || source.exists() {
            return Err(FsOpsError::Io(std::io::Error::other(
                "move postcondition verification failed",
            )));
        }

        let now = Utc::now();
        let cs_id = format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        Ok(ChangeSet {
            id: cs_id,
            task_id: task_id.to_string(),
            created_at: now,
            capability_id: "file.move".to_string(),
            layer: "E3".to_string(),
            operations: vec![ChangeOp::Move {
                from: source.display().to_string(),
                to: dest.display().to_string(),
                fs_id: Some(post_id),
                post_hash,
            }],
            backup_bytes: 0,
            status: ChangeSetStatus::Applied,
            undo_expires_at: now + Duration::days(self.retention_days),
            summary: format!("移动 {} → {}", source.display(), dest.display()),
        })
    }

    /// E3 Native Copy (`openat2` + verified write, no overwrite).
    pub fn copy_file(
        &self,
        task_id: &str,
        source: &Path,
        dest: &Path,
    ) -> Result<ChangeSet, FsOpsError> {
        let (src_parent_fd, src_leaf) = self.ensure_parent_dirfd(source)?;
        Self::ensure_leaf_not_symlink(&src_parent_fd, &src_leaf, source)?;
        let (pre_hash, _, _) = self.hash_and_identity(source)?;
        let (dst_parent_fd, dst_leaf) = self.ensure_parent_dirfd(dest)?;

        self.copy_fd_verified(
            &src_parent_fd,
            &src_leaf,
            &dst_parent_fd,
            &dst_leaf,
            &pre_hash,
        )?;
        let (post_hash, _, _) = self.hash_and_identity(dest)?;

        let now = Utc::now();
        let cs_id = format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        Ok(ChangeSet {
            id: cs_id,
            task_id: task_id.to_string(),
            created_at: now,
            capability_id: "file.copy".to_string(),
            layer: "E3".to_string(),
            operations: vec![ChangeOp::Copy {
                from: source.display().to_string(),
                to: dest.display().to_string(),
                post_hash,
            }],
            backup_bytes: 0,
            status: ChangeSetStatus::Applied,
            undo_expires_at: now + Duration::days(self.retention_days),
            summary: format!("复制 {} → {}", source.display(), dest.display()),
        })
    }

    /// E3 Native Trash following freedesktop Trash spec (§8.5).
    pub fn trash_file(&self, task_id: &str, target: &Path) -> Result<ChangeSet, FsOpsError> {
        let (src_parent_fd, src_leaf) = self.ensure_parent_dirfd(target)?;
        Self::ensure_leaf_not_symlink(&src_parent_fd, &src_leaf, target)?;
        let (pre_hash, _, _) = self.hash_and_identity(target)?;

        let stamp = uuid::Uuid::new_v4().simple().to_string();
        let leaf_str = target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("trashed_item");
        let trash_entry_name = format!("{}_{}", &stamp[..8], leaf_str);
        let trash_data_path = self.trash_dir.join("files").join(&trash_entry_name);
        let trash_info_path = self
            .trash_dir
            .join("info")
            .join(format!("{}.trashinfo", trash_entry_name));

        let info_body = format!(
            "[Trash Info]\nPath={}\nDeletionDate={}\n",
            target.display(),
            Utc::now().format("%Y-%m-%dT%H:%M:%S")
        );
        fs::write(&trash_info_path, info_body)?;

        // Copy verified from openat2 source fd into trash_data_path, then unlinkat original.
        let src_fd = self.openat2_beneath(
            &src_parent_fd,
            Path::new(
                target
                    .file_name()
                    .ok_or_else(|| FsOpsError::InvalidPath(target.display().to_string()))?,
            ),
            libc::O_RDONLY as u64,
            0,
        )?;
        let mut src_file = File::from(src_fd);
        let mut dst_file = File::options()
            .write(true)
            .create_new(true)
            .open(&trash_data_path)?;
        std::io::copy(&mut src_file, &mut dst_file)?;
        dst_file.sync_all()?;

        // SAFETY: `src_parent_fd` and `src_leaf` are validated above.
        let rc = unsafe { libc::unlinkat(src_parent_fd.as_raw_fd(), src_leaf.as_ptr(), 0) };
        if rc < 0 {
            let _ = fs::remove_file(&trash_data_path);
            let _ = fs::remove_file(&trash_info_path);
            return Err(FsOpsError::Io(std::io::Error::last_os_error()));
        }

        let now = Utc::now();
        let cs_id = format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        Ok(ChangeSet {
            id: cs_id,
            task_id: task_id.to_string(),
            created_at: now,
            capability_id: "file.trash".to_string(),
            layer: "E3".to_string(),
            operations: vec![ChangeOp::Trash {
                original_path: target.display().to_string(),
                trash_data_path: trash_data_path.display().to_string(),
                trash_info_path: trash_info_path.display().to_string(),
                pre_hash,
            }],
            backup_bytes: 0,
            status: ChangeSetStatus::Applied,
            undo_expires_at: now + Duration::days(self.retention_days),
            summary: format!("移入回收站 {}", target.display()),
        })
    }

    /// Write/Overwrite an authorized file with backup protection & quota enforcement (§9.2).
    pub fn write_file_reversible(
        &self,
        task_id: &str,
        target: &Path,
        new_bytes: &[u8],
    ) -> Result<ChangeSet, FsOpsError> {
        let (parent_fd, leaf_c) = self.ensure_parent_dirfd(target)?;
        let leaf_path = Path::new(
            target
                .file_name()
                .ok_or_else(|| FsOpsError::InvalidPath(target.display().to_string()))?,
        );
        let cs_id = format!("cs_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        let now = Utc::now();

        // Check if target already exists
        let existing = self.openat2_beneath(&parent_fd, leaf_path, libc::O_RDONLY as u64, 0);
        match existing {
            Ok(old_fd) => {
                Self::ensure_leaf_not_symlink(&parent_fd, &leaf_c, target)?;
                let (pre_hash, _, old_len) = self.hash_and_identity(target)?;

                // Enforce 25% single-file cap and total quota cap (§9.2).
                let max_single = self.quota_bytes / 4;
                let used = self.current_backup_usage_bytes()?;
                let remaining = self.quota_bytes.saturating_sub(used);
                if old_len > max_single || old_len > remaining {
                    return Err(FsOpsError::BackupQuotaExceeded {
                        needed: old_len,
                        limit: max_single.min(remaining),
                    });
                }

                let backup_path = self.backup_dir.join(format!("{}_0.bak", cs_id));
                let backup_bytes = Self::backup_fd_to_path(old_fd, &backup_path)?;

                // Write atomically via temp file in same parent_fd + renameat2 replace
                let tmp_name = format!(
                    ".intentos_tmp_{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..8]
                );
                let tmp_c = CString::new(tmp_name.as_bytes()).unwrap();
                let tmp_fd = self.openat2_beneath(
                    &parent_fd,
                    Path::new(&tmp_name),
                    (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL) as u64,
                    0o644,
                )?;
                {
                    let mut tmp_file = File::from(tmp_fd);
                    tmp_file.write_all(new_bytes)?;
                    tmp_file.sync_all()?;
                }
                // SAFETY: Replace target inside verified `parent_fd`.
                let rc = unsafe {
                    libc::renameat(
                        parent_fd.as_raw_fd(),
                        tmp_c.as_ptr(),
                        parent_fd.as_raw_fd(),
                        leaf_c.as_ptr(),
                    )
                };
                if rc < 0 {
                    unsafe {
                        libc::unlinkat(parent_fd.as_raw_fd(), tmp_c.as_ptr(), 0);
                    }
                    let _ = fs::remove_file(&backup_path);
                    return Err(FsOpsError::Io(std::io::Error::last_os_error()));
                }

                let (post_hash, _, _) = self.hash_and_identity(target)?;
                Ok(ChangeSet {
                    id: cs_id,
                    task_id: task_id.to_string(),
                    created_at: now,
                    capability_id: "file.write".to_string(),
                    layer: "E3".to_string(),
                    operations: vec![ChangeOp::Overwrite {
                        path: target.display().to_string(),
                        backup_path: backup_path.display().to_string(),
                        pre_hash,
                        post_hash,
                    }],
                    backup_bytes,
                    status: ChangeSetStatus::Applied,
                    undo_expires_at: now + Duration::days(self.retention_days),
                    summary: format!("覆盖写入 {}（已备份旧版本）", target.display()),
                })
            }
            Err(FsOpsError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                let fd = self.openat2_beneath(
                    &parent_fd,
                    leaf_path,
                    (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL) as u64,
                    0o644,
                )?;
                {
                    let mut f = File::from(fd);
                    f.write_all(new_bytes)?;
                    f.sync_all()?;
                }
                let (post_hash, _, _) = self.hash_and_identity(target)?;
                Ok(ChangeSet {
                    id: cs_id,
                    task_id: task_id.to_string(),
                    created_at: now,
                    capability_id: "file.write".to_string(),
                    layer: "E3".to_string(),
                    operations: vec![ChangeOp::Create {
                        path: target.display().to_string(),
                        post_hash,
                    }],
                    backup_bytes: 0,
                    status: ChangeSetStatus::Applied,
                    undo_expires_at: now + Duration::days(self.retention_days),
                    summary: format!("新建文件 {}", target.display()),
                })
            }
            Err(other) => Err(other),
        }
    }

    /// Undo a file-level ChangeSet in reverse order with `post_hash` conflict detection (§9.3).
    pub fn undo_file_operations(&self, cs: &ChangeSet) -> Result<UndoOutcome, FsOpsError> {
        if cs.status != ChangeSetStatus::Applied {
            return Err(FsOpsError::NotUndoable(cs.status));
        }
        if Utc::now() > cs.undo_expires_at {
            return Err(FsOpsError::UndoExpired(cs.undo_expires_at.to_rfc3339()));
        }

        let mut restored_ops = 0usize;
        let mut conflicts = Vec::new();

        for op in cs.operations.iter().rev() {
            match op {
                ChangeOp::Move {
                    from,
                    to,
                    post_hash,
                    ..
                } => {
                    let from_path = Path::new(from);
                    let to_path = Path::new(to);
                    let (cur_hash, _, _) = self.hash_and_identity(to_path)?;
                    if &cur_hash != post_hash {
                        conflicts.push(format!(
                            "{} 在移动后已被外部修改，保留原位置并取消逆向覆盖",
                            to
                        ));
                        continue;
                    }
                    let _ = self.move_file(&cs.task_id, to_path, from_path)?;
                    restored_ops += 1;
                }
                ChangeOp::Copy { to, post_hash, .. }
                | ChangeOp::Create {
                    path: to,
                    post_hash,
                } => {
                    let to_path = Path::new(to);
                    let (cur_hash, _, _) = self.hash_and_identity(to_path)?;
                    if &cur_hash != post_hash {
                        conflicts.push(format!("{} 在生成后已被修改，未删除以保护用户内容", to));
                        continue;
                    }
                    let _ = self.trash_file(&cs.task_id, to_path)?;
                    restored_ops += 1;
                }
                ChangeOp::Trash {
                    original_path,
                    trash_data_path,
                    trash_info_path,
                    pre_hash,
                } => {
                    let orig = Path::new(original_path);
                    if orig.exists() {
                        conflicts.push(format!("原路径 {} 已存在新文件", original_path));
                        continue;
                    }
                    let (dst_parent_fd, dst_leaf) = self.ensure_parent_dirfd(orig)?;
                    let dst_leaf_path = Path::new(orig.file_name().unwrap());
                    let dst_fd = self.openat2_beneath(
                        &dst_parent_fd,
                        dst_leaf_path,
                        (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL) as u64,
                        0o644,
                    )?;
                    let mut src = File::open(trash_data_path)?;
                    let mut dst = File::from(dst_fd);
                    std::io::copy(&mut src, &mut dst)?;
                    dst.sync_all()?;
                    let _ = dst_leaf;
                    let (restored_hash, _, _) = self.hash_and_identity(orig)?;
                    if &restored_hash != pre_hash {
                        return Err(FsOpsError::Io(std::io::Error::other(
                            "trash restore hash mismatch",
                        )));
                    }
                    let _ = fs::remove_file(trash_data_path);
                    let _ = fs::remove_file(trash_info_path);
                    restored_ops += 1;
                }
                ChangeOp::Overwrite {
                    path,
                    backup_path,
                    pre_hash,
                    post_hash,
                } => {
                    let target = Path::new(path);
                    let cur_hash = self
                        .hash_and_identity(target)
                        .map(|(h, _, _)| h)
                        .unwrap_or_default();
                    let backup_bytes = fs::read(backup_path)?;
                    if cur_hash != *post_hash {
                        // Conflict resolution (§9.3): preserve current file AND save restored version alongside!
                        let conflict_copy = PathBuf::from(format!(
                            "{}.restored-{}",
                            path,
                            cs.id.trim_start_matches("cs_")
                        ));
                        let _ =
                            self.write_file_reversible(&cs.task_id, &conflict_copy, &backup_bytes)?;
                        conflicts.push(format!(
                            "{} 已被后续修改，已保留当前版本并将旧版本恢复至 {}",
                            path,
                            conflict_copy.display()
                        ));
                        continue;
                    }
                    // Restore directly over unmodified post_hash file
                    let (parent_fd, leaf_c) = self.ensure_parent_dirfd(target)?;
                    let tmp_name = format!(".intentos_undo_{}", cs.id);
                    let tmp_c = CString::new(tmp_name.as_bytes()).unwrap();
                    let tmp_fd = self.openat2_beneath(
                        &parent_fd,
                        Path::new(&tmp_name),
                        (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL) as u64,
                        0o644,
                    )?;
                    {
                        let mut tf = File::from(tmp_fd);
                        tf.write_all(&backup_bytes)?;
                        tf.sync_all()?;
                    }
                    unsafe {
                        libc::renameat(
                            parent_fd.as_raw_fd(),
                            tmp_c.as_ptr(),
                            parent_fd.as_raw_fd(),
                            leaf_c.as_ptr(),
                        );
                    }
                    let (restored_hash, _, _) = self.hash_and_identity(target)?;
                    if &restored_hash != pre_hash {
                        return Err(FsOpsError::Io(std::io::Error::other(
                            "overwrite undo hash mismatch",
                        )));
                    }
                    let _ = fs::remove_file(backup_path);
                    restored_ops += 1;
                }
                ChangeOp::Setting { .. } => {
                    // Handled by SystemSettingsEngine in Core.
                }
            }
        }

        Ok(UndoOutcome {
            changeset_id: cs.id.clone(),
            restored_ops,
            conflicts,
        })
    }

    pub fn current_backup_usage_bytes(&self) -> Result<u64, FsOpsError> {
        let mut total = 0u64;
        if !self.backup_dir.exists() {
            return Ok(0);
        }
        for entry in fs::read_dir(&self.backup_dir)? {
            let entry = entry?;
            if let Ok(meta) = entry.metadata()
                && meta.is_file()
            {
                total = total.saturating_add(meta.len());
            }
        }
        Ok(total)
    }

    fn copy_fd_verified(
        &self,
        src_parent_fd: &OwnedFd,
        src_leaf: &CString,
        dst_parent_fd: &OwnedFd,
        dst_leaf: &CString,
        expected_hash: &str,
    ) -> Result<(), FsOpsError> {
        let src_rel = Path::new(std::ffi::OsStr::from_bytes(src_leaf.as_bytes()));
        let dst_rel = Path::new(std::ffi::OsStr::from_bytes(dst_leaf.as_bytes()));
        let src_fd = self.openat2_beneath(src_parent_fd, src_rel, libc::O_RDONLY as u64, 0)?;
        let dst_fd = match self.openat2_beneath(
            dst_parent_fd,
            dst_rel,
            (libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL) as u64,
            0o644,
        ) {
            Ok(fd) => fd,
            Err(FsOpsError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(FsOpsError::TargetAlreadyExists(
                    dst_rel.display().to_string(),
                ));
            }
            Err(e) => return Err(e),
        };

        let mut src_file = File::from(src_fd);
        let mut dst_file = File::from(dst_fd);
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = src_file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            dst_file.write_all(&buf[..n])?;
        }
        dst_file.sync_all()?;
        let got_hash = format!("sha256:{}", hex::encode(hasher.finalize()));
        if got_hash != expected_hash {
            unsafe {
                libc::unlinkat(dst_parent_fd.as_raw_fd(), dst_leaf.as_ptr(), 0);
            }
            return Err(FsOpsError::Io(std::io::Error::other(
                "copied file sha256 verification failed",
            )));
        }
        Ok(())
    }

    fn backup_fd_to_path(src_fd: OwnedFd, backup_path: &Path) -> Result<u64, FsOpsError> {
        let mut src_file = File::from(src_fd);
        let mut dst_file = File::options()
            .write(true)
            .create_new(true)
            .open(backup_path)?;
        // Try zero-copy FICLONE reflink first (Btrfs/XFS); silently fall back to copy on ext4/tmpfs.
        // SAFETY: `FICLONE` takes source fd by value and clones blocks if supported by FS.
        let cloned = unsafe { libc::ioctl(dst_file.as_raw_fd(), FICLONE, src_file.as_raw_fd()) };
        if cloned == 0 {
            let len = dst_file.metadata()?.len();
            return Ok(len);
        }
        let copied = std::io::copy(&mut src_file, &mut dst_file)?;
        dst_file.sync_all()?;
        Ok(copied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn test_engine() -> (TempDir, SafeFsEngine, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let auth = tmp.path().join("workspace");
        let backup = tmp.path().join("undo");
        let trash = tmp.path().join("trash");
        fs::create_dir_all(&auth).unwrap();
        let engine = SafeFsEngine::new(vec![auth.clone()], vec![], backup, trash).unwrap();
        (tmp, engine, auth)
    }

    #[test]
    fn move_and_undo_roundtrip_verifies_hash() {
        let (_tmp, engine, auth) = test_engine();
        let src = auth.join("downloads/paper.pdf");
        fs::create_dir_all(src.parent().unwrap()).unwrap();
        fs::write(&src, b"PDF-CONTENT-2026").unwrap();
        let (orig_hash, _, _) = engine.hash_and_identity(&src).unwrap();

        let dst = auth.join("papers/2026/paper.pdf");
        let cs = engine.move_file("task_1", &src, &dst).unwrap();
        assert!(!src.exists());
        assert!(dst.exists());

        let outcome = engine.undo_file_operations(&cs).unwrap();
        assert_eq!(outcome.restored_ops, 1);
        assert!(outcome.conflicts.is_empty());
        assert!(src.exists());
        assert!(!dst.exists());
        let (restored_hash, _, _) = engine.hash_and_identity(&src).unwrap();
        assert_eq!(orig_hash, restored_hash);
    }

    #[test]
    fn blocks_symlink_escape_via_openat2() {
        let (tmp, engine, auth) = test_engine();
        let outside_secret = tmp.path().join("outside_secret.txt");
        fs::write(&outside_secret, b"TOP_SECRET").unwrap();

        let evil_dir = auth.join("link_out");
        symlink(tmp.path(), &evil_dir).unwrap();

        let escaped_target = evil_dir.join("outside_secret.txt");
        let err = engine.open_readonly_safe(&escaped_target).unwrap_err();
        assert!(
            matches!(err, FsOpsError::EscapeBlocked(_)),
            "expected EscapeBlocked, got {:?}",
            err
        );
    }

    #[test]
    fn blocks_parent_traversal_and_forbidden_paths() {
        let (_tmp, engine, auth) = test_engine();
        let traversal = auth.join("sub/../../etc/passwd");
        assert!(matches!(
            engine.open_readonly_safe(&traversal),
            Err(FsOpsError::EscapeBlocked(_))
        ));

        let ssh_key = PathBuf::from("/home/user/.ssh/id_ed25519");
        assert!(engine.is_forbidden(&ssh_key));
    }

    #[test]
    fn overwrite_backup_undo_and_conflict_detection() {
        let (_tmp, engine, auth) = test_engine();
        let readme = auth.join("README.md");
        fs::write(&readme, b"v1 original").unwrap();

        let cs = engine
            .write_file_reversible("task_2", &readme, b"v2 updated")
            .unwrap();
        assert_eq!(fs::read(&readme).unwrap(), b"v2 updated");
        assert!(cs.backup_bytes > 0);

        // Undo without conflict restores v1 cleanly
        let out = engine.undo_file_operations(&cs).unwrap();
        assert_eq!(out.restored_ops, 1);
        assert_eq!(fs::read(&readme).unwrap(), b"v1 original");

        // Now test conflict detection when modified externally after write
        let cs2 = engine
            .write_file_reversible("task_3", &readme, b"v2 again")
            .unwrap();
        fs::write(&readme, b"v3 user manual edit").unwrap();
        let out2 = engine.undo_file_operations(&cs2).unwrap();
        assert_eq!(out2.conflicts.len(), 1);
        // User manual edit preserved!
        assert_eq!(fs::read(&readme).unwrap(), b"v3 user manual edit");
    }

    #[test]
    fn quota_exceeded_upgrades_to_destructive_error() {
        let (_tmp, engine, auth) = test_engine();
        let tiny_engine = engine.with_quota(100, 30); // max single = 25 bytes
        let big = auth.join("big.bin");
        fs::write(&big, vec![42u8; 64]).unwrap();
        let err = tiny_engine
            .write_file_reversible("task_q", &big, b"small")
            .unwrap_err();
        assert!(matches!(err, FsOpsError::BackupQuotaExceeded { .. }));
    }

    #[test]
    fn sensitivity_classification_and_approve_path_scope_with_openat2_confinement() {
        let (tmp, engine, auth) = test_engine();

        // 1. Forbidden tier: ~/.ssh/id_ed25519, /etc/shadow, /etc/gshadow, /etc/sudoers
        for forbidden in [
            "/home/user/.ssh/id_ed25519",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/sudoers",
            "/home/user/.gnupg/secring.gpg",
            "/home/user/.config/intentos/config.toml",
        ] {
            let p = Path::new(forbidden);
            assert!(engine.is_forbidden(p), "{} must be forbidden", forbidden);
            assert_eq!(
                engine.classify_path_sensitivity(p),
                PathSensitivity::Forbidden
            );
            assert!(matches!(
                engine.approve_path_scope(p),
                Err(FsOpsError::ForbiddenPath(_))
            ));
        }

        // 2. NormalUserSpace vs SensitiveDotPath vs OutsideScope
        let normal_file = auth.join("桌面/paper_main.docx");
        assert_eq!(
            engine.classify_path_sensitivity(&normal_file),
            PathSensitivity::NormalUserSpace
        );
        let dot_inside_auth = auth.join(".env");
        assert_eq!(
            engine.classify_path_sensitivity(&dot_inside_auth),
            PathSensitivity::SensitiveDotPath
        );
        assert_eq!(
            engine.classify_path_sensitivity(Path::new("/home/user/.config/demo.conf")),
            PathSensitivity::SensitiveDotPath
        );
        assert_eq!(
            engine.classify_path_sensitivity(Path::new("/opt/demo/test.txt")),
            PathSensitivity::OutsideScope
        );

        // 3. Outside directory before approval -> OutsideAuthorizedScope; after approve_path_scope -> openat2 succeeds!
        let outside_dir = tmp.path().join("opt_demo");
        fs::create_dir_all(&outside_dir).unwrap();
        let outside_file = outside_dir.join("test.txt");
        fs::write(&outside_file, b"approved-content").unwrap();

        assert_eq!(
            engine.classify_path_sensitivity(&outside_file),
            PathSensitivity::OutsideScope
        );
        assert!(matches!(
            engine.open_readonly_safe(&outside_file),
            Err(FsOpsError::OutsideAuthorizedScope(_))
        ));

        let approved_scope = engine.approve_path_scope(&outside_file).unwrap();
        assert_eq!(approved_scope, outside_dir);
        assert_eq!(engine.list_approved_roots(), vec![outside_dir.clone()]);
        assert_eq!(
            engine.classify_path_sensitivity(&outside_file),
            PathSensitivity::NormalUserSpace
        );

        // openat2 read & reversible write now work inside approved_scope
        let mut content = String::new();
        engine
            .open_readonly_safe(&outside_file)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "approved-content");

        let cs = engine
            .write_file_reversible("task_apr_1", &outside_file, b"updated-via-approval")
            .unwrap();
        assert_eq!(fs::read(&outside_file).unwrap(), b"updated-via-approval");
        engine.undo_file_operations(&cs).unwrap();
        assert_eq!(fs::read(&outside_file).unwrap(), b"approved-content");

        // Symlink escape inside approved_scope STILL blocked by openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)!
        let symlink_escape = outside_dir.join("escape_passwd");
        symlink("/etc/passwd", &symlink_escape).unwrap();
        assert!(matches!(
            engine.open_readonly_safe(&symlink_escape),
            Err(FsOpsError::EscapeBlocked(_))
        ));

        // Revoking approved root restores OutsideScope confinement
        assert!(engine.revoke_approved_root(&approved_scope));
        assert!(engine.list_approved_roots().is_empty());
        assert_eq!(
            engine.classify_path_sensitivity(&outside_file),
            PathSensitivity::OutsideScope
        );
        assert!(matches!(
            engine.open_readonly_safe(&outside_file),
            Err(FsOpsError::OutsideAuthorizedScope(_))
        ));
    }
}
