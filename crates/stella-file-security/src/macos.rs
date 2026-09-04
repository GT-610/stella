//! Safe boundary around the macOS extended-ACL query API.

use std::{ffi::c_void, fs::File, io, os::fd::AsRawFd, ptr};

const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
const ACL_FIRST_ENTRY: libc::c_int = 0;
const ACL_NEXT_ENTRY: libc::c_int = -1;
const ACL_EXTENDED_ALLOW: libc::c_int = 1;
const ACL_EXTENDED_DENY: libc::c_int = 2;
const UUID_LENGTH: usize = 16;

type RawAcl = *mut c_void;
type RawAclEntry = *mut c_void;

unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> RawAcl;
    fn acl_get_entry(acl: RawAcl, entry_id: libc::c_int, entry: *mut RawAclEntry) -> libc::c_int;
    fn acl_get_tag_type(entry: RawAclEntry, tag: *mut libc::c_int) -> libc::c_int;
    fn acl_get_qualifier(entry: RawAclEntry) -> *mut c_void;
    fn acl_get_permset_mask_np(entry: RawAclEntry, mask: *mut u64) -> libc::c_int;
    fn acl_free(object: *mut c_void) -> libc::c_int;
    fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> libc::c_int;
}

struct NativeAcl(RawAcl);

impl Drop for NativeAcl {
    fn drop(&mut self) {
        // SAFETY: acl_get_fd_np returned this owned ACL object and it is freed once here.
        let _ = unsafe { acl_free(self.0) };
    }
}

struct NativeQualifier(*mut c_void);

impl Drop for NativeQualifier {
    fn drop(&mut self) {
        // SAFETY: acl_get_qualifier returned this owned qualifier and it is freed once here.
        let _ = unsafe { acl_free(self.0) };
    }
}

/// Returns whether a macOS extended ACL grants non-owner access to an open file.
///
/// The query uses the existing file descriptor, so a pathname replacement cannot
/// redirect validation to another inode. Deny entries and zero-permission allow
/// entries do not grant access.
///
/// # Errors
///
/// Returns an operating-system error if the ACL, tag, permission, qualifier, or
/// owner UUID cannot be queried safely.
pub fn extended_acl_grants_non_owner_access(file: &File, owner_uid: u32) -> io::Result<bool> {
    let expected_owner = owner_uuid(owner_uid)?;
    // SAFETY: file.as_raw_fd() is valid for this call and the returned object is owned.
    let raw_acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if raw_acl.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        return Err(error);
    }
    let acl = NativeAcl(raw_acl);
    let mut entry = ptr::null_mut();
    let mut entry_id = ACL_FIRST_ENTRY;
    loop {
        // SAFETY: acl remains live and entry points to writable storage for the result.
        if unsafe { acl_get_entry(acl.0, entry_id, &raw mut entry) } != 0 {
            let error = io::Error::last_os_error();
            if entry_id == ACL_NEXT_ENTRY && error.raw_os_error() == Some(libc::EINVAL) {
                return Ok(false);
            }
            return Err(error);
        }
        entry_id = ACL_NEXT_ENTRY;

        let mut tag = 0;
        // SAFETY: entry was initialized by a successful acl_get_entry call.
        if unsafe { acl_get_tag_type(entry, &raw mut tag) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if tag == ACL_EXTENDED_DENY {
            continue;
        }
        if tag != ACL_EXTENDED_ALLOW {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "macOS returned an unsupported extended ACL tag",
            ));
        }

        let mut permissions = 0_u64;
        // SAFETY: entry was initialized by a successful acl_get_entry call.
        if unsafe { acl_get_permset_mask_np(entry, &raw mut permissions) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if permissions == 0 {
            continue;
        }

        // SAFETY: entry is live and the returned qualifier is independently owned.
        let raw_qualifier = unsafe { acl_get_qualifier(entry) };
        if raw_qualifier.is_null() {
            return Err(io::Error::last_os_error());
        }
        let qualifier = NativeQualifier(raw_qualifier);
        // SAFETY: a macOS extended ACL qualifier is a UUID with UUID_LENGTH bytes.
        let principal_uuid =
            unsafe { std::slice::from_raw_parts(qualifier.0.cast::<u8>(), UUID_LENGTH) };
        if principal_uuid != expected_owner {
            return Ok(true);
        }
    }
}

fn owner_uuid(owner_uid: u32) -> io::Result<[u8; UUID_LENGTH]> {
    let mut uuid = [0_u8; UUID_LENGTH];
    // SAFETY: uuid is writable for UUID_LENGTH bytes; mbr_uid_to_uuid returns an errno value.
    let status = unsafe { mbr_uid_to_uuid(owner_uid, uuid.as_mut_ptr()) };
    if status == 0 {
        Ok(uuid)
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::OpenOptions,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::extended_acl_grants_non_owner_access;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn distinguishes_owner_and_inherited_non_owner_acl_entries() {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "stella-file-security-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create ACL test directory");

        let owner_file = create_file(&directory.join("owner.pk8"));
        let owner_uid = owner_file.metadata().expect("read owner metadata").uid();
        assert!(
            !extended_acl_grants_non_owner_access(&owner_file, owner_uid)
                .expect("inspect empty extended ACL")
        );
        let owner_name = command_stdout("/usr/bin/id", &["-un"]);
        install_acl(
            &directory.join("owner.pk8"),
            &format!("{owner_name} allow read"),
        );
        assert!(
            !extended_acl_grants_non_owner_access(&owner_file, owner_uid)
                .expect("inspect owner-only extended ACL")
        );
        drop(owner_file);

        install_acl(&directory, "everyone allow read,file_inherit");
        let inherited_file = create_file(&directory.join("inherited.pk8"));
        let inherited_uid = inherited_file
            .metadata()
            .expect("read inherited file metadata")
            .uid();
        assert!(
            extended_acl_grants_non_owner_access(&inherited_file, inherited_uid)
                .expect("inspect inherited extended ACL")
        );
        drop(inherited_file);

        std::fs::remove_dir_all(directory).expect("remove ACL test directory");
    }

    fn create_file(path: &Path) -> std::fs::File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create ACL test file")
    }

    fn install_acl(path: &Path, acl: &str) {
        let status = Command::new("/bin/chmod")
            .args(["+a", acl])
            .arg(path)
            .status()
            .expect("run chmod for ACL test");
        assert!(status.success(), "chmod could not install test ACL");
    }

    fn command_stdout(program: &str, arguments: &[&str]) -> String {
        let output = Command::new(program)
            .args(arguments)
            .output()
            .expect("run ACL test command");
        assert!(output.status.success(), "ACL test command failed");
        String::from_utf8(output.stdout)
            .expect("ACL test command returned UTF-8")
            .trim()
            .to_owned()
    }
}
