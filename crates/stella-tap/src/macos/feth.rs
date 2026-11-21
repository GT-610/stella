//! Persistent feth lifecycle, ownership, MTU, and link-state handling.

use std::{
    fs::{DirBuilder, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::OwnedFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

use fs2::FileExt;

use super::sys;
use crate::{Result, TapError, TapOperation, MAX_TAP_MTU};

const LOCK_DIRECTORY: &str = "/var/run/stella";
const LOCK_DIRECTORY_MODE: u32 = 0o700;
const LOCK_FILE_MODE: u32 = 0o600;
const METADATA_PREFIX: &str = "stella-feth-v1";
const OWNERSHIP_PREFIX: &str = "stella-feth-v2";
const METADATA_LINE_LIMIT: u64 = 512;

/// Sets the single user authorized to own new feth pair lock records.
///
/// The root helper calls this once with its `--allow-uid` value so that a
/// second helper instance started for a different user cannot take over an
/// idle pair owned by the first user. When unset, records stay unbound and
/// validation does not require a UID match, which keeps direct privileged
/// development paths working.
pub(crate) fn set_authorized_uid(uid: u32) {
    let _ = AUTHORIZED_UID.set(uid);
}

static AUTHORIZED_UID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

#[derive(Clone, Copy)]
struct InterfaceState {
    mtu: u16,
    flags: libc::c_short,
}

pub(super) struct PreparedFethPair {
    visible: String,
    peer: String,
    lock: Option<File>,
    control: OwnedFd,
    visible_created: bool,
    peer_created: bool,
    visible_original: Option<InterfaceState>,
    peer_original: Option<InterfaceState>,
    effective_mtu: u16,
    mac_address: [u8; 6],
    committed: bool,
}

impl PreparedFethPair {
    pub(super) fn prepare(visible: &str, peer: &str, requested_mtu: u16) -> Result<Self> {
        let mut lock = acquire_pair_lock(visible, peer)?;
        let visible_exists = sys::interface_exists(visible)
            .map_err(|source| TapError::io(TapOperation::QueryDeviceState, source))?;
        let peer_exists = sys::interface_exists(peer)
            .map_err(|source| TapError::io(TapOperation::QueryDeviceState, source))?;
        validate_ownership(&mut lock, visible, peer, visible_exists || peer_exists)?;

        let control = sys::open_control_socket()
            .map_err(|source| TapError::io(TapOperation::OpenDevice, source))?;
        // XNU copies net.link.fake.max_mtu into each feth when it is created.
        // Raising the sysctl after creation cannot enlarge that interface's ceiling.
        ensure_feth_mtu_limit(MAX_TAP_MTU)?;
        let visible_original = visible_exists
            .then(|| interface_state(&control, visible))
            .transpose()?;
        let peer_original = peer_exists
            .then(|| interface_state(&control, peer))
            .transpose()?;
        let mut prepared = Self {
            visible: visible.to_owned(),
            peer: peer.to_owned(),
            lock: Some(lock),
            control,
            visible_created: false,
            peer_created: false,
            visible_original,
            peer_original,
            effective_mtu: requested_mtu,
            mac_address: [0; 6],
            committed: false,
        };
        if !visible_exists {
            sys::create_interface(&prepared.control, visible)
                .map_err(|source| TapError::io(TapOperation::CreateDevice, source))?;
            prepared.visible_created = true;
        }
        if !peer_exists {
            sys::create_interface(&prepared.control, peer)
                .map_err(|source| TapError::io(TapOperation::CreateDevice, source))?;
            prepared.peer_created = true;
        }
        ensure_interface_mtu_capacity(&prepared.control, visible, MAX_TAP_MTU)?;
        ensure_interface_mtu_capacity(&prepared.control, peer, MAX_TAP_MTU)?;
        if prepared.visible_created {
            sys::set_interface_mac(&prepared.control, visible, random_local_unicast_mac())
                .map_err(|source| TapError::io(TapOperation::SetMac, source))?;
        }
        pair_interfaces(&prepared.control, peer, visible)?;
        prepared.effective_mtu = requested_mtu;
        set_pair_mtu(&prepared.control, visible, peer, prepared.effective_mtu)?;
        sys::set_interface_up(&prepared.control, peer, true)
            .map_err(|source| TapError::io(TapOperation::SetDeviceState, source))?;
        sys::set_interface_up(&prepared.control, visible, true)
            .map_err(|source| TapError::io(TapOperation::SetDeviceState, source))?;
        prepared.mac_address = sys::interface_mac(&prepared.control, visible)
            .map_err(|source| TapError::io(TapOperation::QueryMac, source))?;
        Ok(prepared)
    }

    pub(super) const fn effective_mtu(&self) -> u16 {
        self.effective_mtu
    }

    pub(super) const fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    pub(super) fn commit(mut self) -> Result<FethPair> {
        let mut lock = self.lock.take().ok_or(TapError::Closed)?;
        write_ownership(&mut lock, &self.visible, &self.peer)?;
        self.committed = true;
        Ok(FethPair {
            visible: self.visible.clone(),
            peer: self.peer.clone(),
            lock,
            enabled: true,
        })
    }
}

impl Drop for PreparedFethPair {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Some(state) = self.peer_original {
            let _ = sys::set_interface_mtu(&self.control, &self.peer, state.mtu);
            let _ = sys::set_interface_flags(&self.control, &self.peer, state.flags);
        }
        if let Some(state) = self.visible_original {
            let _ = sys::set_interface_mtu(&self.control, &self.visible, state.mtu);
            let _ = sys::set_interface_flags(&self.control, &self.visible, state.flags);
        }
        if self.peer_created {
            let _ = sys::destroy_interface(&self.peer);
        }
        if self.visible_created {
            let _ = sys::destroy_interface(&self.visible);
        }
    }
}

pub(super) struct FethPair {
    visible: String,
    peer: String,
    // RAII guard: holding the exclusive lock file prevents a second process
    // from claiming the same feth pair. The field is never read directly.
    #[allow(
        dead_code,
        reason = "exclusive lock is held for its lifetime, not read"
    )]
    lock: File,
    enabled: bool,
}

impl FethPair {
    pub(super) fn set_mtu(&self, mtu: u16) -> Result<()> {
        let control = sys::open_control_socket()
            .map_err(|source| TapError::io(TapOperation::OpenDevice, source))?;
        ensure_feth_mtu_limit(mtu)?;
        ensure_interface_mtu_capacity(&control, &self.visible, mtu)?;
        ensure_interface_mtu_capacity(&control, &self.peer, mtu)?;
        set_pair_mtu(&control, &self.visible, &self.peer, mtu)
    }

    pub(super) fn disable(&mut self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let control = sys::open_control_socket()
            .map_err(|source| TapError::io(TapOperation::OpenDevice, source))?;
        let peer_result = sys::set_interface_up(&control, &self.peer, false);
        let visible_result = sys::set_interface_up(&control, &self.visible, false);
        if let Err(source) = visible_result {
            return Err(TapError::io(TapOperation::SetDeviceState, source));
        }
        if let Err(source) = peer_result {
            return Err(TapError::io(TapOperation::SetDeviceState, source));
        }
        self.enabled = false;
        Ok(())
    }
}

impl Drop for FethPair {
    fn drop(&mut self) {
        let _ = self.disable();
    }
}

fn interface_state(control: &OwnedFd, name: &str) -> Result<InterfaceState> {
    let mtu = sys::interface_mtu(control, name)
        .map_err(|source| TapError::io(TapOperation::QueryMtu, source))?;
    let flags = sys::interface_flags(control, name)
        .map_err(|source| TapError::io(TapOperation::QueryDeviceState, source))?;
    Ok(InterfaceState { mtu, flags })
}

fn set_pair_mtu(control: &OwnedFd, visible: &str, peer: &str, mtu: u16) -> Result<()> {
    let visible_previous = sys::interface_mtu(control, visible)
        .map_err(|source| TapError::io(TapOperation::QueryMtu, source))?;
    sys::set_interface_mtu(control, visible, mtu)
        .map_err(|source| TapError::io(TapOperation::SetMtu, source))?;
    if let Err(update) = sys::set_interface_mtu(control, peer, mtu) {
        return match sys::set_interface_mtu(control, visible, visible_previous) {
            Ok(()) => Err(TapError::io(TapOperation::SetMtu, update)),
            Err(rollback) => Err(TapError::PairMtuRollbackFailed {
                failed_interface: peer.to_owned(),
                rollback_interface: visible.to_owned(),
                update,
                rollback,
            }),
        };
    }
    Ok(())
}

fn ensure_feth_mtu_limit(requested: u16) -> Result<()> {
    let current = sys::feth_max_mtu()
        .map_err(|source| TapError::io(TapOperation::QueryFethMtuLimit, source))?;
    let Some(target) = feth_mtu_limit_update(current, requested) else {
        return Ok(());
    };
    sys::set_feth_max_mtu(target)
        .map_err(|source| TapError::io(TapOperation::SetFethMtuLimit, source))?;
    let updated = sys::feth_max_mtu()
        .map_err(|source| TapError::io(TapOperation::QueryFethMtuLimit, source))?;
    if updated < u32::from(requested) {
        return Err(TapError::io(
            TapOperation::SetFethMtuLimit,
            io::Error::other(format!(
                "macOS retained feth MTU limit {updated} below requested MTU {requested}"
            )),
        ));
    }
    Ok(())
}

fn ensure_interface_mtu_capacity(control: &OwnedFd, interface: &str, required: u16) -> Result<()> {
    let available = sys::interface_max_mtu(control, interface)
        .map_err(|source| TapError::io(TapOperation::QueryDeviceMtuLimit, source))?;
    if available < u32::from(required) {
        return Err(TapError::FethMtuTooSmall {
            interface: interface.to_owned(),
            required,
            available,
        });
    }
    Ok(())
}

fn feth_mtu_limit_update(current: u32, requested: u16) -> Option<u16> {
    (current < u32::from(requested)).then_some(MAX_TAP_MTU)
}

fn pair_interfaces(control: &OwnedFd, peer: &str, visible: &str) -> Result<()> {
    let visible_peer = sys::interface_peer(control, visible)
        .map_err(|source| TapError::io(TapOperation::QueryPeer, source))?;
    let packet_peer = sys::interface_peer(control, peer)
        .map_err(|source| TapError::io(TapOperation::QueryPeer, source))?;
    match (visible_peer.as_deref(), packet_peer.as_deref()) {
        (Some(actual_peer), Some(actual_visible))
            if actual_peer == peer && actual_visible == visible =>
        {
            Ok(())
        }
        (None, None) => sys::set_interface_peer(control, peer, visible)
            .map_err(|source| TapError::io(TapOperation::PairInterfaces, source)),
        _ => Err(TapError::DeviceOwnershipConflict {
            name: visible.to_owned(),
            peer_name: peer.to_owned(),
        }),
    }
}

fn random_local_unicast_mac() -> [u8; 6] {
    let mut address = [0_u8; 6];
    // SAFETY: `address` is writable for its full length. arc4random_buf has no failure mode.
    unsafe { libc::arc4random_buf(address.as_mut_ptr().cast(), address.len()) };
    normalize_local_unicast_mac(address)
}

fn normalize_local_unicast_mac(mut address: [u8; 6]) -> [u8; 6] {
    address[0] = (address[0] | 0x02) & 0xfe;
    address
}

fn acquire_pair_lock(name: &str, peer_name: &str) -> Result<File> {
    ensure_lock_directory()?;
    let (first, second) = if name <= peer_name {
        (name, peer_name)
    } else {
        (peer_name, name)
    };
    let path = Path::new(LOCK_DIRECTORY).join(format!("tap-{first}-{second}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(LOCK_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| TapError::io(TapOperation::AcquireDeviceLock, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| TapError::io(TapOperation::AcquireDeviceLock, source))?;
    if !metadata.file_type().is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(TapError::io(
            TapOperation::AcquireDeviceLock,
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "macOS TAP lock file must be a root-owned private regular file",
            ),
        ));
    }
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        Err(source) if source.kind() == io::ErrorKind::WouldBlock => Err(TapError::DeviceBusy {
            name: name.to_owned(),
            peer_name: peer_name.to_owned(),
        }),
        Err(source) => Err(TapError::io(TapOperation::AcquireDeviceLock, source)),
    }
}

fn ensure_lock_directory() -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(LOCK_DIRECTORY_MODE);
    match builder.create(LOCK_DIRECTORY) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(TapError::io(TapOperation::AcquireDeviceLock, source)),
    }
    let metadata = std::fs::symlink_metadata(LOCK_DIRECTORY)
        .map_err(|source| TapError::io(TapOperation::AcquireDeviceLock, source))?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(TapError::io(
            TapOperation::AcquireDeviceLock,
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "macOS TAP lock directory must be a root-owned private directory",
            ),
        ));
    }
    Ok(())
}

fn validate_ownership(
    lock: &mut File,
    visible: &str,
    peer: &str,
    interface_exists: bool,
) -> Result<()> {
    let length = lock
        .metadata()
        .map_err(|source| TapError::io(TapOperation::VerifyDeviceOwnership, source))?
        .len();
    if length > METADATA_LINE_LIMIT {
        return Err(TapError::DeviceOwnershipConflict {
            name: visible.to_owned(),
            peer_name: peer.to_owned(),
        });
    }
    lock.seek(SeekFrom::Start(0))
        .map_err(|source| TapError::io(TapOperation::VerifyDeviceOwnership, source))?;
    let mut actual = String::new();
    lock.read_to_string(&mut actual)
        .map_err(|source| TapError::io(TapOperation::VerifyDeviceOwnership, source))?;
    let matching = actual.is_empty() && !interface_exists
        || record_matches_authorized_user(&actual, visible, peer);
    if matching {
        Ok(())
    } else {
        Err(TapError::DeviceOwnershipConflict {
            name: visible.to_owned(),
            peer_name: peer.to_owned(),
        })
    }
}

/// Compares one lock record against the requested pair and authorized user.
///
/// Legacy version-1 records carry no owner UID and are accepted unchanged so
/// existing deployments upgrade to a bound record on the next commit. Every
/// version-2 record must name the exact pair, and when a helper context is
/// active the record's UID must equal the caller's authorized UID. This stops
/// a helper instance started for one local user from taking over an idle pair
/// opened through a helper for another user.
fn record_matches_authorized_user(record: &str, visible: &str, peer: &str) -> bool {
    match parse_ownership_record(record) {
        Some((record_uid, record_visible, record_peer)) => {
            record_visible == visible
                && record_peer == peer
                && match (AUTHORIZED_UID.get().copied(), record_uid) {
                    // Direct privileged path without a helper context accepts
                    // both bound and unbound records.
                    (None, _) | (Some(_), None) => true,
                    // The lock is bound to the authorized local user.
                    (Some(authorized), Some(record_uid)) => authorized == record_uid,
                }
        }
        None => record == ownership_record(visible, peer, None),
    }
}

/// Parses one `stella-feth-v2` record into its UID, visible, and peer names.
fn parse_ownership_record(record: &str) -> Option<(Option<u32>, &str, &str)> {
    let mut lines = record.lines();
    if lines.next()? != OWNERSHIP_PREFIX {
        return None;
    }
    let visible = lines.next()?.strip_prefix("visible=")?;
    let peer = lines.next()?.strip_prefix("peer=")?;
    let uid = lines
        .next()?
        .strip_prefix("uid=")?
        .parse::<u32>()
        .ok()
        .map(Some)?;
    if lines.next().is_some() {
        return None;
    }
    Some((uid, visible, peer))
}

fn write_ownership(lock: &mut File, visible: &str, peer: &str) -> Result<()> {
    let record = ownership_record(visible, peer, AUTHORIZED_UID.get().copied());
    lock.set_len(0)
        .map_err(|source| TapError::io(TapOperation::RecordDeviceOwnership, source))?;
    lock.seek(SeekFrom::Start(0))
        .map_err(|source| TapError::io(TapOperation::RecordDeviceOwnership, source))?;
    lock.write_all(record.as_bytes())
        .and_then(|()| lock.sync_data())
        .map_err(|source| TapError::io(TapOperation::RecordDeviceOwnership, source))
}

fn ownership_record(visible: &str, peer: &str, authorized_uid: Option<u32>) -> String {
    match authorized_uid {
        Some(uid) => format!("{OWNERSHIP_PREFIX}\nvisible={visible}\npeer={peer}\nuid={uid}\n"),
        None => format!("{METADATA_PREFIX}\nvisible={visible}\npeer={peer}\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        feth_mtu_limit_update, normalize_local_unicast_mac, ownership_record,
        parse_ownership_record, record_matches_authorized_user,
    };
    use crate::MAX_TAP_MTU;

    #[test]
    fn ownership_record_preserves_interface_roles() {
        assert_eq!(
            ownership_record("feth100", "feth101", None),
            "stella-feth-v1\nvisible=feth100\npeer=feth101\n"
        );
        assert_ne!(
            ownership_record("feth100", "feth101", None),
            ownership_record("feth101", "feth100", None)
        );
        assert_eq!(
            ownership_record("feth100", "feth101", Some(501)),
            "stella-feth-v2\nvisible=feth100\npeer=feth101\nuid=501\n"
        );
    }

    #[test]
    fn ownership_matching_binds_the_authorized_user() {
        let bound = ownership_record("feth100", "feth101", Some(501));
        let legacy = ownership_record("feth100", "feth101", None);
        // Records only match the exact pair names.
        assert!(!record_matches_authorized_user(
            &bound, "feth101", "feth100"
        ));
        assert!(!record_matches_authorized_user(
            &legacy, "feth101", "feth100"
        ));

        // Parsing tolerates neither extra lines nor malformed UIDs.
        assert_eq!(
            parse_ownership_record("stella-feth-v2\nvisible=feth100\npeer=feth101\nuid=x\n"),
            None
        );
        assert_eq!(
            parse_ownership_record("stella-feth-v2\nvisible=feth100\npeer=feth101\nuid=1\njunk\n"),
            None
        );
        assert_eq!(
            parse_ownership_record("stella-feth-v1\nvisible=feth100\npeer=feth101\n"),
            None
        );
        assert_eq!(
            parse_ownership_record("stella-feth-v2\nvisible=feth100\npeer=feth101\nuid=501\n"),
            Some((Some(501), "feth100", "feth101"))
        );

        // Without a helper context (direct privileged development path) both
        // legacy and bound records match the exact pair names; the
        // UID-binding branch itself runs under the root-only macos_tap test.
        assert!(record_matches_authorized_user(
            &legacy, "feth100", "feth101"
        ));
        assert!(record_matches_authorized_user(&bound, "feth100", "feth101"));
    }

    #[test]
    fn generated_mac_is_locally_administered_unicast() {
        assert_eq!(normalize_local_unicast_mac([0; 6]), [0x02, 0, 0, 0, 0, 0]);
        let address = normalize_local_unicast_mac([0xff; 6]);
        assert_eq!(address[0], 0xfe);
        assert_eq!(address[1..], [0xff; 5]);
    }

    #[test]
    fn feth_mtu_limit_is_only_raised_and_never_lowered() {
        assert_eq!(feth_mtu_limit_update(2_048, 4_082), Some(MAX_TAP_MTU));
        assert_eq!(feth_mtu_limit_update(4_082, 4_082), None);
        assert_eq!(feth_mtu_limit_update(10_000, MAX_TAP_MTU), None);
    }
}
