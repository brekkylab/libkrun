use std::env;
use std::fs::{self, File, Permissions};
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::{self as unix_fs, PermissionsExt};

use anyhow::{Context, bail};
use nix::errno::Errno;
use nix::mount::{self, MsFlags};
use nix::unistd;

/// Mount, treating EBUSY (already mounted) as success.
fn mount_or_busy(
    src: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: MsFlags,
) -> anyhow::Result<()> {
    match mount::mount(src, target, fstype, flags, None::<&str>) {
        Ok(()) => Ok(()),
        Err(Errno::EBUSY) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("mount {target}")),
    }
}

pub fn mount_filesystems() -> anyhow::Result<()> {
    let base_flags = MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME;
    fs::create_dir_all("/dev").context("create /dev")?;
    fs::create_dir_all("/proc").context("create /proc")?;
    fs::create_dir_all("/sys").context("create /sys")?;

    mount_or_busy(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_RELATIME,
    )?;

    // Best-effort: allow nested virtualization by unprivileged processes.
    match fs::set_permissions("/dev/kvm", Permissions::from_mode(0o666)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => eprintln!("chmod(/dev/kvm): {e}"),
        _ => {}
    }

    mount_or_busy(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NODEV | base_flags,
    )?;

    mount_or_busy(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NODEV | base_flags,
    )?;

    mount_or_busy(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MsFlags::MS_NODEV | base_flags,
    )?;

    fs::create_dir_all("/dev/pts").context("create /dev/pts")?;
    fs::create_dir_all("/dev/shm").context("create /dev/shm")?;

    mount_or_busy(Some("devpts"), "/dev/pts", Some("devpts"), base_flags)?;
    mount_or_busy(Some("tmpfs"), "/dev/shm", Some("tmpfs"), base_flags)?;

    // Best-effort; may already exist.
    let _ = unix_fs::symlink("/proc/self/fd", "/dev/fd");

    Ok(())
}

/// Returns true if path is listed as a mount point in /proc/mounts.
///
/// Uses /proc/mounts instead of stat() because Podman arranges tmpfs
/// auto-mounts that would be triggered by a stat call.
pub fn is_mount_point(path: &str) -> bool {
    let Ok(f) = File::open("/proc/mounts") else {
        return false;
    };
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let mut parts = line.split_whitespace();
        let _ = parts.next(); // device
        if parts.next() == Some(path) {
            return true;
        }
    }
    false
}

pub fn mount_tmpfs(path: &str) -> anyhow::Result<()> {
    mount::mount(
        Some("tmpfs"),
        path,
        Some("tmpfs"),
        MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RELATIME,
        None::<&str>,
    )
    .with_context(|| format!("mount tmpfs at {path}"))
}

/// Mount /dev/vda as ext4, then pivot root into it.
#[cfg(any(feature = "amd-sev", feature = "tdx"))]
pub fn mount_tee_block_device() -> anyhow::Result<()> {
    fs::create_dir_all("/tmp/vda").context("create /tmp/vda")?;

    mount_or_busy(
        Some("/dev/vda"),
        "/tmp/vda",
        Some("ext4"),
        MsFlags::MS_RELATIME,
    )?;
    unistd::chdir("/tmp/vda").context("chdir /tmp/vda")?;

    mount_or_busy(Some("."), "/", None::<&str>, MsFlags::MS_MOVE)?;
    unistd::chroot(".").context("chroot .")
}

/// Mount source onto target, trying each non-virtual filesystem listed in
/// /proc/filesystems when fstype is None.
pub fn try_mount(
    source: &str,
    target: &str,
    fstype: Option<&str>,
    flags: MsFlags,
    data: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(fs) = fstype {
        return mount::mount(Some(source), target, Some(fs), flags, data)
            .with_context(|| format!("mount {source} -> {target} as {fs}"));
    }

    let f = File::open("/proc/filesystems").context("open /proc/filesystems")?;
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        if line.starts_with("nodev") {
            continue;
        }
        let fs = line.trim();
        if mount::mount(Some(source), target, Some(fs), flags, data).is_ok() {
            return Ok(());
        }
    }
    bail!("no supported filesystem found for {source}")
}

/// The two halves of an overlay root, as the boot names them.
///
/// A boot that names both is asking for a root it can write to without writing into the
/// image: the lower is the image, read-only and shared with every other machine started
/// from it, and the upper is this one's alone. `KRUN_BLOCK_ROOT_DEVICE` names the single
/// device that becomes the root as it is, and the two forms are exclusive.
const LOWER_DEVICE: &str = "KRUN_BLOCK_LOWER_DEVICE";
const LOWER_FSTYPE: &str = "KRUN_BLOCK_LOWER_FSTYPE";
const UPPER_DEVICE: &str = "KRUN_BLOCK_UPPER_DEVICE";
const UPPER_FSTYPE: &str = "KRUN_BLOCK_UPPER_FSTYPE";

/// Where each half is mounted before the two are stacked. On the initial root, which the
/// pivot below leaves behind -- both stay mounted afterwards, reachable by no path.
const LOWER_AT: &str = "/lower";
const UPPER_AT: &str = "/upper";

/// The two directories overlayfs wants, on the upper device rather than beside it: a
/// workdir has to be on the same filesystem as the upperdir, and the upper is the only
/// filesystem here that is writable and outlives the boot.
const UPPER_DIR: &str = "/upper/upper";
const WORK_DIR: &str = "/upper/work";

/// Handle KRUN_BLOCK_ROOT_DEVICE: mount the block device at /newroot,
/// ask the virtiofs device to remove the temporary root, then pivot.
///
/// `KRUN_BLOCK_LOWER_DEVICE` and `KRUN_BLOCK_UPPER_DEVICE` are the other way to name a
/// root -- an overlay of the two, stacked at the same /newroot and pivoted onto the same
/// way. See [`mount_overlay_root`].
pub fn mount_block_root_device() -> anyhow::Result<()> {
    let overlay = overlay_devices()?;
    let single = env::var_os("KRUN_BLOCK_ROOT_DEVICE");
    if overlay.is_none() && single.is_none() {
        return Ok(());
    }

    fs::create_dir_all("/newroot").context("create /newroot")?;

    match overlay {
        Some((lower, upper)) => mount_overlay_root(&lower, &upper)?,
        None => {
            let krun_root = single
                .expect("checked above")
                .to_string_lossy()
                .into_owned();
            let fstype = env::var("KRUN_BLOCK_ROOT_FSTYPE").ok();
            let options = env::var("KRUN_BLOCK_ROOT_OPTIONS").ok();

            try_mount(
                &krun_root,
                "/newroot",
                fstype.as_deref(),
                MsFlags::empty(),
                options.as_deref(),
            )?;
        }
    }

    // While `/` is still the virtiofs mount, because after the move it is under no path
    // and the exit code has nowhere to go. See `exec::hold_virtiofs_root`.
    crate::exec::hold_virtiofs_root();

    unistd::chdir("/newroot").context("chdir /newroot")?;

    mount::mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
        .context("pivot root MS_MOVE")?;

    unistd::chroot(".").context("chroot after block root pivot")?;

    // Re-mount standard filesystems now that we're in the new root.
    mount_filesystems()?;

    Ok(())
}

/// The devices an overlay root is made of, or `None` for a boot that asked for no overlay.
///
/// One of the two on its own is refused rather than ignored: it is a boot that meant to ask
/// for an overlay, and falling through to the single-device path would hand it a root that
/// is either read-only or empty, with nothing said about why.
fn overlay_devices() -> anyhow::Result<Option<(String, String)>> {
    match (env::var(LOWER_DEVICE).ok(), env::var(UPPER_DEVICE).ok()) {
        (Some(lower), Some(upper)) => Ok(Some((lower, upper))),
        (None, None) => Ok(None),
        (Some(_), None) => bail!("{LOWER_DEVICE} was set without {UPPER_DEVICE}"),
        (None, Some(_)) => bail!("{UPPER_DEVICE} was set without {LOWER_DEVICE}"),
    }
}

/// Stack the writable upper over the read-only lower, as the root at /newroot.
///
/// Reads fall through to the lower, writes land on the upper and stay there for as long as
/// that device does. Neither device is the root itself, so what a guest deletes or replaces
/// is recorded on the upper as a whiteout rather than written into the image.
///
/// Two block devices rather than a writable virtiofs root, because overlayfs cannot copy up
/// from a virtiofs lower -- and without copy-up, editing any file the image shipped fails.
fn mount_overlay_root(lower: &str, upper: &str) -> anyhow::Result<()> {
    fs::create_dir_all(LOWER_AT).with_context(|| format!("create {LOWER_AT}"))?;
    fs::create_dir_all(UPPER_AT).with_context(|| format!("create {UPPER_AT}"))?;

    // MS_RDONLY is not a preference: a device attached read-only is one the kernel refuses
    // to mount without it, and the lower of an overlay is never written to anyway.
    try_mount(
        lower,
        LOWER_AT,
        env::var(LOWER_FSTYPE).ok().as_deref(),
        MsFlags::MS_RDONLY,
        None,
    )?;
    try_mount(
        upper,
        UPPER_AT,
        env::var(UPPER_FSTYPE).ok().as_deref(),
        MsFlags::empty(),
        None,
    )?;

    // On the upper itself, so that a device carrying an earlier session's writes is picked
    // up where it left off rather than started again.
    fs::create_dir_all(UPPER_DIR).with_context(|| format!("create {UPPER_DIR}"))?;
    fs::create_dir_all(WORK_DIR).with_context(|| format!("create {WORK_DIR}"))?;

    let options = format!("lowerdir={LOWER_AT},upperdir={UPPER_DIR},workdir={WORK_DIR}");
    mount::mount(
        Some("overlay"),
        "/newroot",
        Some("overlay"),
        MsFlags::empty(),
        Some(options.as_str()),
    )
    .with_context(|| format!("mount overlay -> /newroot ({options})"))
}

pub fn mount_shared_root() -> anyhow::Result<()> {
    mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_SHARED,
        None::<&str>,
    )
    .context("set MS_SHARED on root mount")
}
