// SPDX-License-Identifier: Apache-2.0
//
//! The mounts a boot asks for beyond its root.
//!
//! `/.krun_config.json` carries a `mounts` list, and until now the init read one entry
//! out of it -- the first tmpfs -- and dropped the rest. What the rest is for is a host
//! directory shared into the guest: the host attaches a virtiofs device with a tag, and
//! the guest mounts that tag somewhere. Without this the device is there and nothing
//! ever mounts it.
//!
//! # After the root, and never before
//!
//! These are mounted once the root is whatever it is going to be -- after a boot that
//! pivots onto a block device or an overlay has pivoted. A mount made before the pivot
//! would be on the root that the pivot leaves behind, reachable by no path afterwards.
//!
//! # Read-only is the host's to enforce
//!
//! Nothing here asks for `MS_RDONLY`. A share the host attached read-only is one whose
//! virtiofs server refuses every write, whatever the guest mounted it with, and that is
//! the guarantee -- a mount flag the guest could remount away is not one.

use std::fs;

use anyhow::{Context, Result};
use nix::mount::{self, MsFlags};

/// One entry of the config's `mounts`, as far as this cares.
pub struct Mount {
    pub source: String,
    pub fs_type: String,
    pub destination: String,
}

/// Mount each of `mounts`, making the directory it goes on.
///
/// The destination is created rather than required: a share is named by a host that
/// cannot see inside the image, and a path that happens not to exist there is not a
/// mistake anyone could have avoided. On the root this is the writable layer, so the
/// directory is made once and found on every boot after.
///
/// A mount that fails stops the boot. The alternative is a workload that runs with its
/// data silently missing, which is worse than not running.
pub fn mount_all(mounts: &[Mount]) -> Result<()> {
    for m in mounts {
        fs::create_dir_all(&m.destination).with_context(|| format!("create {}", m.destination))?;

        mount::mount(
            Some(m.source.as_str()),
            m.destination.as_str(),
            Some(m.fs_type.as_str()),
            MsFlags::empty(),
            None::<&str>,
        )
        .with_context(|| format!("mount {} -> {} as {}", m.source, m.destination, m.fs_type))?;
    }
    Ok(())
}
