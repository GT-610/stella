//! TAP-Windows Adapter V9 backend.

use std::{
    ffi::{c_void, OsString},
    fmt,
    fs::{File, OpenOptions},
    io,
    mem::{align_of, size_of, MaybeUninit},
    os::windows::{
        ffi::OsStringExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex, Weak},
    thread,
    time::{Duration, Instant},
};

use windows::{
    core::{Error as WindowsError, BOOL, GUID, HRESULT, HSTRING, PCWSTR, PSTR, PWSTR},
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            DiInstallDevice, SetupDiCallClassInstaller, SetupDiClassNameFromGuidW,
            SetupDiCreateDeviceInfoList, SetupDiCreateDeviceInfoW, SetupDiDestroyDeviceInfoList,
            SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceInstallParamsW,
            SetupDiOpenDevRegKey, SetupDiSetClassInstallParamsW, SetupDiSetDeviceRegistryPropertyW,
            SetupDiSetSelectedDevice, DICD_GENERATE_ID, DICS_FLAG_GLOBAL, DIF_REGISTERDEVICE,
            DIF_REMOVE, DIGCF_PRESENT, DIINSTALLDEVICE_FLAGS, DIREG_DRV, DI_NEEDREBOOT,
            DI_NEEDRESTART, DI_REMOVEDEVICE_GLOBAL, GUID_DEVCLASS_NET, HDEVINFO, SPDRP_HARDWAREID,
            SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_DEVINSTALL_PARAMS_W,
            SP_REMOVEDEVICE_PARAMS,
        },
        Foundation::{
            ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_NOT_FOUND,
            ERROR_NO_DATA, ERROR_NO_MORE_ITEMS, ERROR_OPERATION_ABORTED, ERROR_PATH_NOT_FOUND,
            HANDLE, NO_ERROR, WIN32_ERROR,
        },
        NetworkManagement::{
            IpHelper::{
                GetAdaptersAddresses, GetIpInterfaceEntry, InitializeIpInterfaceEntry,
                SetIpInterfaceEntry, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST,
                GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
                GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH, MIB_IPINTERFACE_ROW,
            },
            Ndis::NET_LUID_LH,
        },
        Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC},
        Storage::FileSystem::{ReadFile, WriteFile, FILE_ATTRIBUTE_SYSTEM, FILE_FLAG_OVERLAPPED},
        System::{
            Registry::{RegCloseKey, RegGetValueW, HKEY, KEY_READ, RRF_RT_REG_SZ},
            SystemInformation::GetSystemDirectoryW,
            Threading::CreateEventW,
            IO::{CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED},
        },
    },
};

use crate::{
    AddressFamily, Result, TapCancellation, TapCancellationHandle, TapConfig, TapDevice, TapError,
    TapOperation, MAX_TAP_MTU, MIN_TAP_MTU,
};

const TAP_DEVICE_PREFIX: &str = r"\\.\Global\";
const TAP_DEVICE_SUFFIX: &str = ".tap";
const TAP_DESCRIPTION_PREFIX: &str = "tap-windows adapter";
const TAP_HARDWARE_ID: &str = "tap0901";
const TAP_DEVICE_DESCRIPTION: &str = "Stella Virtual Ethernet";
const MINIMUM_DRIVER_MAJOR: u32 = 9;
const TAP_VLAN_ALLOWANCE: u32 = 18;
const DEVICE_APPEARANCE_TIMEOUT: Duration = Duration::from_secs(30);
const DEVICE_APPEARANCE_POLL_INTERVAL: Duration = Duration::from_millis(100);

static DEVICE_MANAGEMENT: Mutex<()> = Mutex::new(());
static NETWORK_DEVICE_CLASS: GUID = GUID_DEVCLASS_NET;

const FILE_DEVICE_UNKNOWN: u32 = 0x22;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const TAP_IOCTL_GET_MAC: u32 = tap_control_code(1);
const TAP_IOCTL_GET_VERSION: u32 = tap_control_code(2);
const TAP_IOCTL_GET_MTU: u32 = tap_control_code(3);
const TAP_IOCTL_SET_MEDIA_STATUS: u32 = tap_control_code(6);
const TAP_IOCTL_PRIORITY_BEHAVIOR: u32 = tap_control_code(11);

const TAP_PRIORITY_BEHAVIOR_ENABLED: u32 = 1;

/// Installed TAP-Windows adapter metadata safe to display and persist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsTapAdapter {
    /// Windows connection-friendly name.
    pub friendly_name: String,
    /// Canonical interface GUID including braces.
    pub interface_id: String,
    /// Driver-supplied adapter description.
    pub description: String,
    /// Current Windows IP-interface MTU reported during enumeration.
    pub system_mtu: u32,
}

/// TAP-Windows driver version returned by the device control interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsTapDriverVersion {
    /// Driver major version.
    pub major: u32,
    /// Driver minor version.
    pub minor: u32,
    /// Whether the installed driver is a debug build.
    pub debug: bool,
}

/// Result of ensuring that one named TAP-Windows adapter exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsTapProvision {
    adapter: WindowsTapAdapter,
    created: bool,
}

impl WindowsTapProvision {
    /// Returns the adapter selected or created for the requested name.
    #[must_use]
    pub const fn adapter(&self) -> &WindowsTapAdapter {
        &self.adapter
    }

    /// Returns whether this call created a new persistent Windows device.
    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }
}

/// Result of removing one named TAP-Windows adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsTapRemoval {
    removed: bool,
    reboot_required: bool,
}

impl WindowsTapRemoval {
    /// Returns whether a matching adapter existed and was removed.
    #[must_use]
    pub const fn removed(self) -> bool {
        self.removed
    }

    /// Returns whether Windows requires a reboot to finish the removal.
    #[must_use]
    pub const fn reboot_required(self) -> bool {
        self.reboot_required
    }
}

#[derive(Clone)]
struct AdapterCandidate {
    metadata: WindowsTapAdapter,
    luid: NET_LUID_LH,
}

/// Cancellation control for one currently open TAP-Windows device.
#[derive(Clone)]
pub struct WindowsTapCancellation {
    file: Weak<File>,
}

impl TapCancellation for WindowsTapCancellation {
    fn cancel_pending_io(&self) -> Result<()> {
        let Some(file) = self.file.upgrade() else {
            return Ok(());
        };
        // SAFETY: `file` owns a live Windows handle for the duration of this
        // call. A null OVERLAPPED pointer intentionally selects all operations.
        match unsafe { CancelIoEx(file_handle(&file), None) } {
            Ok(()) => Ok(()),
            Err(error) if is_win32_error(&error, ERROR_NOT_FOUND) => Ok(()),
            Err(error) => Err(TapError::io(
                TapOperation::CancelIo,
                windows_error_to_io(&error),
            )),
        }
    }
}

impl fmt::Debug for WindowsTapCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsTapCancellation")
            .field("device_open", &self.file.strong_count().ne(&0))
            .finish_non_exhaustive()
    }
}

/// Exclusive complete-frame handle for one TAP-Windows Adapter V9 instance.
pub struct WindowsTapDevice {
    file: Arc<File>,
    adapter: WindowsTapAdapter,
    luid: NET_LUID_LH,
    config: TapConfig,
    mac_address: [u8; 6],
    driver_version: WindowsTapDriverVersion,
    driver_mtu: u32,
    media_connected: bool,
}

impl WindowsTapDevice {
    /// Enumerates installed adapters whose driver description identifies
    /// TAP-Windows.
    ///
    /// # Errors
    ///
    /// Returns a typed operating-system or adapter-metadata error.
    pub fn installed_adapters() -> Result<Vec<WindowsTapAdapter>> {
        Ok(enumerate_candidates()?
            .into_iter()
            .map(|candidate| candidate.metadata)
            .collect())
    }

    /// Ensures that a persistent TAP-Windows adapter with `name` exists.
    ///
    /// The TAP-Windows driver package must already be installed in the Windows
    /// driver store. Creating a new device requires administrator privileges.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration or operating-system error when the name is
    /// invalid, the driver is unavailable, or Windows cannot create or rename
    /// the device.
    pub fn ensure_adapter(name: &str) -> Result<WindowsTapProvision> {
        let (candidate, created) = ensure_named_candidate(name)?;
        Ok(WindowsTapProvision {
            adapter: candidate.metadata,
            created,
        })
    }

    /// Removes the TAP-Windows adapter matching `selector` when it exists.
    ///
    /// The selector may be the friendly name or interface GUID returned by
    /// [`Self::installed_adapters`]. Removal requires administrator privileges.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when enumeration or device removal
    /// fails, or an ambiguity error when more than one adapter matches.
    pub fn remove_adapter(selector: &str) -> Result<WindowsTapRemoval> {
        let _management = lock_device_management()?;
        let candidates = enumerate_candidates()?;
        let candidate = match select_candidate(candidates, Some(selector)) {
            Ok(candidate) => candidate,
            Err(TapError::AdapterNotFound { .. }) => {
                return Ok(WindowsTapRemoval {
                    removed: false,
                    reboot_required: false,
                });
            }
            Err(error) => return Err(error),
        };
        remove_interface_device(&candidate.metadata.interface_id)
    }

    fn disconnect(&mut self) -> Result<()> {
        if !self.media_connected {
            return Ok(());
        }
        set_media_status(&self.file, false)?;
        self.media_connected = false;
        Ok(())
    }
}

impl TapDevice for WindowsTapDevice {
    fn create(config: &TapConfig) -> Result<Self> {
        config.validate()?;
        let candidate = match config.name.as_deref() {
            Some(name) => ensure_named_candidate(name)?.0,
            None => select_candidate(enumerate_candidates()?, None)?,
        };
        let file = Arc::new(open_device(&candidate.metadata.interface_id)?);
        let driver_version = query_driver_version(&file)?;
        if driver_version.major < MINIMUM_DRIVER_MAJOR {
            return Err(TapError::UnsupportedDriverVersion {
                major: driver_version.major,
                minor: driver_version.minor,
            });
        }
        let mac_address = query_mac_address(&file)?;
        let driver_mtu = query_driver_mtu(&file)?;
        validate_driver_bounds(config, driver_mtu)?;
        configure_priority_behavior(&file)?;
        set_media_status(&file, true)?;

        if let Err(error) = update_interface_mtu(candidate.luid, config.mtu) {
            let _ = set_media_status(&file, false);
            return Err(error);
        }

        Ok(Self {
            file,
            adapter: candidate.metadata,
            luid: candidate.luid,
            config: config.clone(),
            mac_address,
            driver_version,
            driver_mtu,
            media_connected: true,
        })
    }

    fn cancellation_handle(&self) -> TapCancellationHandle {
        Arc::new(WindowsTapCancellation {
            file: Arc::downgrade(&self.file),
        })
    }

    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.config.validate_read_buffer(buf.len())?;
        let length = complete_overlapped(&self.file, TapOperation::ReadFrame, |overlapped| {
            // SAFETY: `buf` remains exclusively borrowed and valid until the
            // helper observes completion; `overlapped` is pinned on its stack.
            unsafe { ReadFile(file_handle(&self.file), Some(buf), None, Some(overlapped)) }
        })?;
        let length = usize::try_from(length).map_err(|error| {
            TapError::io(
                TapOperation::ReadFrame,
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?;
        self.config.validate_frame(length)?;
        Ok(length)
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.config.validate_frame(frame.len())?;
        let written = complete_overlapped(&self.file, TapOperation::WriteFrame, |overlapped| {
            // SAFETY: `frame` remains borrowed and valid until the helper
            // observes completion; `overlapped` is pinned on its stack.
            unsafe { WriteFile(file_handle(&self.file), Some(frame), None, Some(overlapped)) }
        })?;
        let written = usize::try_from(written).map_err(|error| {
            TapError::io(
                TapOperation::WriteFrame,
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?;
        if written != frame.len() {
            return Err(TapError::PartialFrameWrite {
                expected: frame.len(),
                actual: written,
            });
        }
        Ok(())
    }

    fn mac_address(&self) -> Result<[u8; 6]> {
        Ok(self.mac_address)
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        validate_runtime_mtu(&self.config, mtu, self.driver_mtu)?;
        update_interface_mtu(self.luid, mtu)?;
        self.config.mtu = mtu;
        Ok(())
    }

    fn destroy(mut self) -> Result<()> {
        self.disconnect()
    }
}

impl Drop for WindowsTapDevice {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}

impl fmt::Debug for WindowsTapDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsTapDevice")
            .field("adapter", &self.adapter)
            .field("config", &self.config)
            .field("mac_address", &self.mac_address)
            .field("driver_version", &self.driver_version)
            .field("driver_mtu", &self.driver_mtu)
            .field("media_connected", &self.media_connected)
            .finish_non_exhaustive()
    }
}

const fn tap_control_code(request: u32) -> u32 {
    (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (request << 2) | METHOD_BUFFERED
}

struct DeviceInfoSet(HDEVINFO);

impl Drop for DeviceInfoSet {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by a SetupAPI creation function and is
        // owned by this guard until it is destroyed exactly once here.
        let _ = unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: `self.0` is an open registry key owned by this guard.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

fn lock_device_management() -> Result<std::sync::MutexGuard<'static, ()>> {
    DEVICE_MANAGEMENT.lock().map_err(|_| {
        TapError::io(
            TapOperation::CreateDevice,
            io::Error::other("TAP device-management lock was poisoned"),
        )
    })
}

fn ensure_named_candidate(name: &str) -> Result<(AdapterCandidate, bool)> {
    validate_windows_adapter_name(name)?;
    let _management = lock_device_management()?;
    let candidates = enumerate_candidates()?;
    match select_candidate(candidates, Some(name)) {
        Ok(candidate) => return Ok((candidate, false)),
        Err(TapError::AdapterNotFound { .. }) => {}
        Err(error) => return Err(error),
    }
    if looks_like_interface_id(name) {
        return Err(TapError::AdapterNotFound {
            selector: Some(name.to_owned()),
        });
    }
    provision_named_adapter(name).map(|candidate| (candidate, true))
}

fn provision_named_adapter(name: &str) -> Result<AdapterCandidate> {
    let set = create_network_device_info_set()?;
    let mut device = create_tap_device_info(&set)?;
    let mut registered = false;
    let result = (|| {
        register_tap_device(&set, &mut device)?;
        registered = true;
        install_tap_device(&set, &device)?;
        let interface_id = wait_for_net_cfg_instance_id(&set, &device)?;
        let candidate = wait_for_interface_candidate(&interface_id)?;
        rename_interface(&candidate.metadata.friendly_name, name)?;
        wait_for_named_interface_candidate(&interface_id, name)
    })();
    if result.is_err() && registered {
        if let Err(cleanup) = remove_device_info(&set, &device) {
            return Err(TapError::io(
                TapOperation::RemoveDevice,
                io::Error::other(format!(
                    "TAP provisioning failed and the partial device could not be removed: {cleanup}"
                )),
            ));
        }
    }
    result
}

fn create_network_device_info_set() -> Result<DeviceInfoSet> {
    // SAFETY: The class GUID is a valid static network-device GUID and no
    // parent window is required for noninteractive provisioning.
    unsafe { SetupDiCreateDeviceInfoList(Some(&raw const NETWORK_DEVICE_CLASS), None) }
        .map(DeviceInfoSet)
        .map_err(|error| TapError::io(TapOperation::CreateDevice, windows_error_to_io(&error)))
}

fn create_tap_device_info(set: &DeviceInfoSet) -> Result<SP_DEVINFO_DATA> {
    let mut class_name = [0_u16; 256];
    // SAFETY: `class_name` is writable for its complete length and the class
    // GUID is the network adapter class used to create `set`.
    unsafe { SetupDiClassNameFromGuidW(&raw const NETWORK_DEVICE_CLASS, &mut class_name, None) }
        .map_err(|error| TapError::io(TapOperation::CreateDevice, windows_error_to_io(&error)))?;
    let mut device = SP_DEVINFO_DATA {
        cbSize: structure_size::<SP_DEVINFO_DATA>(TapOperation::CreateDevice)?,
        ..SP_DEVINFO_DATA::default()
    };
    // SAFETY: `set` is live, both UTF-16 inputs remain valid for the call,
    // and `device` is initialized with the required structure size.
    unsafe {
        SetupDiCreateDeviceInfoW(
            set.0,
            PCWSTR(class_name.as_ptr()),
            &raw const NETWORK_DEVICE_CLASS,
            &HSTRING::from(TAP_DEVICE_DESCRIPTION),
            None,
            DICD_GENERATE_ID,
            Some(&raw mut device),
        )
    }
    .map_err(|error| TapError::io(TapOperation::CreateDevice, windows_error_to_io(&error)))?;
    // SAFETY: `device` belongs to the live device information set.
    unsafe { SetupDiSetSelectedDevice(set.0, &raw const device) }
        .map_err(|error| TapError::io(TapOperation::CreateDevice, windows_error_to_io(&error)))?;
    Ok(device)
}

fn register_tap_device(set: &DeviceInfoSet, device: &mut SP_DEVINFO_DATA) -> Result<()> {
    let hardware_ids = utf16_multi_string(TAP_HARDWARE_ID);
    // SAFETY: `device` belongs to `set`; the property bytes encode one
    // double-null-terminated UTF-16 hardware ID for the duration of the call.
    unsafe {
        SetupDiSetDeviceRegistryPropertyW(set.0, device, SPDRP_HARDWAREID, Some(&hardware_ids))
    }
    .map_err(|error| TapError::io(TapOperation::CreateDevice, windows_error_to_io(&error)))?;
    // SAFETY: The device information element is complete and selected in the
    // live set; the class installer owns registration side effects.
    unsafe { SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set.0, Some(device)) }
        .map_err(|error| TapError::io(TapOperation::CreateDevice, windows_error_to_io(&error)))
}

fn install_tap_device(set: &DeviceInfoSet, device: &SP_DEVINFO_DATA) -> Result<()> {
    let mut reboot_required = BOOL::default();
    // SAFETY: `device` is registered in `set`; a null driver-info pointer asks
    // Windows to select the best matching package already in the driver store.
    unsafe {
        DiInstallDevice(
            None,
            set.0,
            device,
            None,
            DIINSTALLDEVICE_FLAGS::default(),
            Some(&raw mut reboot_required),
        )
    }
    .map_err(|error| TapError::io(TapOperation::InstallDevice, windows_error_to_io(&error)))?;
    if reboot_required.as_bool() {
        return Err(TapError::io(
            TapOperation::InstallDevice,
            io::Error::other("Windows requires a reboot before the TAP device can be used"),
        ));
    }
    Ok(())
}

fn wait_for_net_cfg_instance_id(set: &DeviceInfoSet, device: &SP_DEVINFO_DATA) -> Result<String> {
    let deadline = Instant::now() + DEVICE_APPEARANCE_TIMEOUT;
    loop {
        match read_net_cfg_instance_id(set, device) {
            Ok(interface_id) => return Ok(canonical_interface_id(&interface_id)),
            Err(error) if is_missing_device_identity(&error) && Instant::now() < deadline => {
                thread::sleep(DEVICE_APPEARANCE_POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}

fn read_net_cfg_instance_id(set: &DeviceInfoSet, device: &SP_DEVINFO_DATA) -> Result<String> {
    // SAFETY: `device` belongs to the live set. The returned driver key is
    // closed by `RegistryKey`.
    let key = unsafe {
        SetupDiOpenDevRegKey(set.0, device, DICS_FLAG_GLOBAL.0, 0, DIREG_DRV, KEY_READ.0)
    }
    .map(RegistryKey)
    .map_err(|error| {
        TapError::io(
            TapOperation::QueryDeviceIdentity,
            windows_error_to_io(&error),
        )
    })?;
    read_registry_string(&key, "NetCfgInstanceId")
}

fn read_registry_string(key: &RegistryKey, value_name: &str) -> Result<String> {
    let value_name = HSTRING::from(value_name);
    let mut byte_length = 0_u32;
    // SAFETY: This sizing call supplies no output pointer and a live byte-count
    // pointer. The registry key and value name remain valid throughout.
    let status = unsafe {
        RegGetValueW(
            key.0,
            PCWSTR::null(),
            &value_name,
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&raw mut byte_length),
        )
    };
    if status != NO_ERROR {
        return Err(TapError::io(
            TapOperation::QueryDeviceIdentity,
            win32_error_to_io(status),
        ));
    }
    if byte_length < 2 || byte_length % 2 != 0 {
        return Err(TapError::io(
            TapOperation::QueryDeviceIdentity,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned an invalid UTF-16 registry string length",
            ),
        ));
    }
    let mut words = vec![
        0_u16;
        usize::try_from(byte_length / 2).map_err(|error| {
            TapError::io(
                TapOperation::QueryDeviceIdentity,
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?
    ];
    // SAFETY: `words` owns exactly `byte_length` writable bytes, and the
    // registry call is constrained to REG_SZ data.
    let status = unsafe {
        RegGetValueW(
            key.0,
            PCWSTR::null(),
            &value_name,
            RRF_RT_REG_SZ,
            None,
            Some(words.as_mut_ptr().cast()),
            Some(&raw mut byte_length),
        )
    };
    if status != NO_ERROR {
        return Err(TapError::io(
            TapOperation::QueryDeviceIdentity,
            win32_error_to_io(status),
        ));
    }
    let length = words
        .iter()
        .position(|word| *word == 0)
        .unwrap_or(words.len());
    String::from_utf16(&words[..length]).map_err(|error| {
        TapError::io(
            TapOperation::QueryDeviceIdentity,
            io::Error::new(io::ErrorKind::InvalidData, error),
        )
    })
}

fn wait_for_interface_candidate(interface_id: &str) -> Result<AdapterCandidate> {
    wait_for_candidate(interface_id, None)
}

fn wait_for_named_interface_candidate(interface_id: &str, name: &str) -> Result<AdapterCandidate> {
    wait_for_candidate(interface_id, Some(name))
}

fn wait_for_candidate(interface_id: &str, name: Option<&str>) -> Result<AdapterCandidate> {
    let deadline = Instant::now() + DEVICE_APPEARANCE_TIMEOUT;
    loop {
        let candidate = enumerate_candidates()?.into_iter().find(|candidate| {
            normalize_interface_id(&candidate.metadata.interface_id)
                .eq_ignore_ascii_case(normalize_interface_id(interface_id))
                && name.is_none_or(|expected| {
                    candidate
                        .metadata
                        .friendly_name
                        .eq_ignore_ascii_case(expected)
                })
        });
        if let Some(candidate) = candidate {
            return Ok(candidate);
        }
        if Instant::now() >= deadline {
            return Err(TapError::io(
                TapOperation::QueryDeviceState,
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the TAP adapter did not become visible before the deadline",
                ),
            ));
        }
        thread::sleep(DEVICE_APPEARANCE_POLL_INTERVAL);
    }
}

fn rename_interface(old_name: &str, new_name: &str) -> Result<()> {
    if old_name.eq_ignore_ascii_case(new_name) {
        return Ok(());
    }
    let netsh = system_directory()?.join("netsh.exe");
    let status = Command::new(netsh)
        .args([
            "interface",
            "set",
            "interface",
            &format!("name={old_name}"),
            &format!("newname={new_name}"),
        ])
        .status()
        .map_err(|error| TapError::io(TapOperation::RenameDevice, error))?;
    if !status.success() {
        return Err(TapError::io(
            TapOperation::RenameDevice,
            io::Error::other(format!("netsh exited with status {status}")),
        ));
    }
    Ok(())
}

fn system_directory() -> Result<PathBuf> {
    let mut buffer = vec![0_u16; 260];
    loop {
        // SAFETY: `buffer` is writable for its full length.
        let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) };
        if length == 0 {
            return Err(TapError::io(
                TapOperation::RenameDevice,
                io::Error::last_os_error(),
            ));
        }
        let length = usize::try_from(length).map_err(|error| {
            TapError::io(
                TapOperation::RenameDevice,
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?;
        if length < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
        }
        buffer.resize(length.saturating_add(1), 0);
    }
}

fn remove_interface_device(interface_id: &str) -> Result<WindowsTapRemoval> {
    // SAFETY: The class GUID and flags request a local snapshot of present
    // network devices; the returned set is owned by `DeviceInfoSet`.
    let set = unsafe {
        SetupDiGetClassDevsW(
            Some(&raw const NETWORK_DEVICE_CLASS),
            PCWSTR::null(),
            None,
            DIGCF_PRESENT,
        )
    }
    .map(DeviceInfoSet)
    .map_err(|error| TapError::io(TapOperation::RemoveDevice, windows_error_to_io(&error)))?;
    let device_info_size = structure_size::<SP_DEVINFO_DATA>(TapOperation::RemoveDevice)?;
    let mut index = 0_u32;
    loop {
        let mut device = SP_DEVINFO_DATA {
            cbSize: device_info_size,
            ..SP_DEVINFO_DATA::default()
        };
        // SAFETY: `device` is writable and initialized with the required size;
        // `index` advances monotonically through the live set.
        match unsafe { SetupDiEnumDeviceInfo(set.0, index, &raw mut device) } {
            Ok(()) => {}
            Err(error) if is_win32_error(&error, ERROR_NO_MORE_ITEMS) => {
                return Ok(WindowsTapRemoval {
                    removed: false,
                    reboot_required: false,
                });
            }
            Err(error) => {
                return Err(TapError::io(
                    TapOperation::RemoveDevice,
                    windows_error_to_io(&error),
                ));
            }
        }
        index = index.saturating_add(1);
        let current_id = match read_net_cfg_instance_id(&set, &device) {
            Ok(value) => value,
            Err(error) if is_missing_device_identity(&error) => continue,
            Err(error) => return Err(error),
        };
        if normalize_interface_id(&current_id)
            .eq_ignore_ascii_case(normalize_interface_id(interface_id))
        {
            let reboot_required = remove_device_info(&set, &device)?;
            if !reboot_required {
                wait_for_interface_removal(interface_id)?;
            }
            return Ok(WindowsTapRemoval {
                removed: true,
                reboot_required,
            });
        }
    }
}

fn wait_for_interface_removal(interface_id: &str) -> Result<()> {
    let deadline = Instant::now() + DEVICE_APPEARANCE_TIMEOUT;
    loop {
        let present = enumerate_candidates()?.iter().any(|candidate| {
            normalize_interface_id(&candidate.metadata.interface_id)
                .eq_ignore_ascii_case(normalize_interface_id(interface_id))
        });
        if !present {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(TapError::io(
                TapOperation::RemoveDevice,
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the TAP adapter remained visible after removal",
                ),
            ));
        }
        thread::sleep(DEVICE_APPEARANCE_POLL_INTERVAL);
    }
}

fn remove_device_info(set: &DeviceInfoSet, device: &SP_DEVINFO_DATA) -> Result<bool> {
    let parameters = SP_REMOVEDEVICE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: structure_size::<SP_CLASSINSTALL_HEADER>(TapOperation::RemoveDevice)?,
            InstallFunction: DIF_REMOVE,
        },
        Scope: DI_REMOVEDEVICE_GLOBAL,
        HwProfile: 0,
    };
    // SAFETY: The removal parameters have the correct structure sizes and
    // remain live while SetupAPI copies them for this device.
    unsafe {
        SetupDiSetClassInstallParamsW(
            set.0,
            Some(device),
            Some(&raw const parameters.ClassInstallHeader),
            structure_size::<SP_REMOVEDEVICE_PARAMS>(TapOperation::RemoveDevice)?,
        )
    }
    .map_err(|error| TapError::io(TapOperation::RemoveDevice, windows_error_to_io(&error)))?;
    // SAFETY: `device` belongs to the live set and now has DIF_REMOVE class
    // installer parameters.
    unsafe { SetupDiCallClassInstaller(DIF_REMOVE, set.0, Some(device)) }
        .map_err(|error| TapError::io(TapOperation::RemoveDevice, windows_error_to_io(&error)))?;
    device_reboot_required(set, device)
}

fn device_reboot_required(set: &DeviceInfoSet, device: &SP_DEVINFO_DATA) -> Result<bool> {
    let mut parameters = SP_DEVINSTALL_PARAMS_W {
        cbSize: structure_size::<SP_DEVINSTALL_PARAMS_W>(TapOperation::QueryDeviceState)?,
        ..SP_DEVINSTALL_PARAMS_W::default()
    };
    // SAFETY: `parameters` is writable and initialized with the exact API
    // structure size; `device` belongs to the live set.
    unsafe { SetupDiGetDeviceInstallParamsW(set.0, Some(device), &raw mut parameters) }.map_err(
        |error| TapError::io(TapOperation::QueryDeviceState, windows_error_to_io(&error)),
    )?;
    Ok(parameters.Flags.contains(DI_NEEDREBOOT) || parameters.Flags.contains(DI_NEEDRESTART))
}

fn validate_windows_adapter_name(name: &str) -> Result<()> {
    if name.is_empty() || name.trim() != name {
        return Err(TapError::InvalidConfig {
            field: "name",
            reason: "must not be empty or have leading or trailing whitespace",
        });
    }
    if name.encode_utf16().count() > 255 {
        return Err(TapError::InvalidConfig {
            field: "name",
            reason: "must fit the 255-character Windows interface-name limit",
        });
    }
    if name
        .chars()
        .any(|character| character.is_control() || r#"\/:*?"<>|"#.contains(character))
    {
        return Err(TapError::InvalidConfig {
            field: "name",
            reason: "contains a character Windows forbids in interface names",
        });
    }
    Ok(())
}

fn looks_like_interface_id(value: &str) -> bool {
    let value = normalize_interface_id(value);
    let groups = value.split('-').collect::<Vec<_>>();
    groups.len() == 5
        && groups
            .iter()
            .zip([8_usize, 4, 4, 4, 12])
            .all(|(group, length)| {
                group.len() == length && group.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
}

fn utf16_multi_string(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .chain([0, 0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn structure_size<T>(operation: TapOperation) -> Result<u32> {
    u32::try_from(size_of::<T>())
        .map_err(|error| TapError::io(operation, io::Error::new(io::ErrorKind::InvalidData, error)))
}

fn is_missing_device_identity(error: &TapError) -> bool {
    matches!(
        error,
        TapError::Io {
            operation: TapOperation::QueryDeviceIdentity,
            source,
        } if matches!(
            source.raw_os_error(),
            Some(code)
                if code == u32_to_i32_bits(ERROR_FILE_NOT_FOUND.0)
                    || code == u32_to_i32_bits(ERROR_PATH_NOT_FOUND.0)
        )
    )
}

fn enumerate_candidates() -> Result<Vec<AdapterCandidate>> {
    let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
        GAA_FLAG_INCLUDE_ALL_INTERFACES.0
            | GAA_FLAG_SKIP_UNICAST.0
            | GAA_FLAG_SKIP_ANYCAST.0
            | GAA_FLAG_SKIP_MULTICAST.0
            | GAA_FLAG_SKIP_DNS_SERVER.0,
    );
    let mut required = 0_u32;
    // SAFETY: A null output pointer with zero length is the documented sizing
    // call. `required` is a live writable `u32`.
    let sizing = unsafe {
        GetAdaptersAddresses(u32::from(AF_UNSPEC.0), flags, None, None, &raw mut required)
    };
    if sizing == ERROR_NO_DATA.0 {
        return Ok(Vec::new());
    }
    if sizing != ERROR_BUFFER_OVERFLOW.0 && sizing != NO_ERROR.0 {
        return Err(TapError::io(
            TapOperation::EnumerateAdapters,
            io::Error::from_raw_os_error(u32_to_i32_bits(sizing)),
        ));
    }
    if required == 0 {
        return Ok(Vec::new());
    }

    for _ in 0..3 {
        let unit_size = size_of::<IP_ADAPTER_ADDRESSES_LH>();
        let required_usize = usize::try_from(required).map_err(|error| {
            TapError::io(
                TapOperation::EnumerateAdapters,
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?;
        let units = required_usize.div_ceil(unit_size);
        let mut storage = vec![MaybeUninit::<IP_ADAPTER_ADDRESSES_LH>::zeroed(); units];
        let capacity = units.checked_mul(unit_size).ok_or_else(|| {
            TapError::io(
                TapOperation::EnumerateAdapters,
                io::Error::new(io::ErrorKind::OutOfMemory, "adapter buffer size overflow"),
            )
        })?;
        let mut available = u32::try_from(capacity).map_err(|error| {
            TapError::io(
                TapOperation::EnumerateAdapters,
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })?;
        // SAFETY: `storage` is aligned for `IP_ADAPTER_ADDRESSES_LH` and owns
        // `available` writable bytes. The OS initializes the returned records.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                flags,
                None,
                Some(storage.as_mut_ptr().cast()),
                &raw mut available,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW.0 {
            required = available;
            continue;
        }
        if status == ERROR_NO_DATA.0 {
            return Ok(Vec::new());
        }
        if status != NO_ERROR.0 {
            return Err(TapError::io(
                TapOperation::EnumerateAdapters,
                io::Error::from_raw_os_error(u32_to_i32_bits(status)),
            ));
        }
        return parse_candidates(&storage);
    }

    Err(TapError::io(
        TapOperation::EnumerateAdapters,
        io::Error::other("adapter list grew across three bounded retries"),
    ))
}

fn parse_candidates(
    storage: &[MaybeUninit<IP_ADAPTER_ADDRESSES_LH>],
) -> Result<Vec<AdapterCandidate>> {
    let byte_length = storage
        .len()
        .checked_mul(size_of::<IP_ADAPTER_ADDRESSES_LH>())
        .ok_or_else(invalid_adapter_data)?;
    let start = storage.as_ptr().cast::<u8>() as usize;
    let end = start
        .checked_add(byte_length)
        .ok_or_else(invalid_adapter_data)?;
    let mut current = storage.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut remaining = storage.len();
    let mut candidates = Vec::new();

    while !current.is_null() {
        let address = current as usize;
        let record_end = address
            .checked_add(size_of::<IP_ADAPTER_ADDRESSES_LH>())
            .ok_or_else(invalid_adapter_data)?;
        if address < start
            || record_end > end
            || address % align_of::<IP_ADAPTER_ADDRESSES_LH>() != 0
            || remaining == 0
        {
            return Err(invalid_adapter_data());
        }

        // SAFETY: The pointer came from `GetAdaptersAddresses`; the bounds,
        // alignment, record size, and bounded traversal were checked above.
        let adapter = unsafe { &*current };
        let description = wide_string(adapter.Description)?;
        if description
            .to_ascii_lowercase()
            .starts_with(TAP_DESCRIPTION_PREFIX)
        {
            let interface_id = narrow_string(adapter.AdapterName)?;
            let friendly_name = wide_string(adapter.FriendlyName)?;
            candidates.push(AdapterCandidate {
                metadata: WindowsTapAdapter {
                    friendly_name,
                    interface_id: canonical_interface_id(&interface_id),
                    description,
                    system_mtu: adapter.Mtu,
                },
                luid: adapter.Luid,
            });
        }

        current = adapter.Next;
        remaining -= 1;
    }

    candidates.sort_by(|left, right| {
        left.metadata
            .friendly_name
            .to_ascii_lowercase()
            .cmp(&right.metadata.friendly_name.to_ascii_lowercase())
            .then_with(|| left.metadata.interface_id.cmp(&right.metadata.interface_id))
    });
    Ok(candidates)
}

fn select_candidate(
    candidates: Vec<AdapterCandidate>,
    selector: Option<&str>,
) -> Result<AdapterCandidate> {
    let selector_owned = selector.map(str::to_owned);
    let mut matching: Vec<_> = match selector {
        Some(selector) => candidates
            .into_iter()
            .filter(|candidate| candidate_matches(candidate, selector))
            .collect(),
        None => candidates,
    };
    match matching.len() {
        0 => Err(TapError::AdapterNotFound {
            selector: selector_owned,
        }),
        1 => matching.pop().ok_or_else(invalid_adapter_data),
        count => Err(TapError::AmbiguousAdapters {
            selector: selector_owned,
            count,
        }),
    }
}

fn candidate_matches(candidate: &AdapterCandidate, selector: &str) -> bool {
    candidate
        .metadata
        .friendly_name
        .eq_ignore_ascii_case(selector.trim())
        || normalize_interface_id(&candidate.metadata.interface_id)
            == normalize_interface_id(selector)
}

fn canonical_interface_id(value: &str) -> String {
    format!("{{{}}}", normalize_interface_id(value).to_ascii_uppercase())
}

fn normalize_interface_id(value: &str) -> &str {
    value
        .trim()
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or_else(|| value.trim())
}

fn device_path(interface_id: &str) -> String {
    format!(
        "{TAP_DEVICE_PREFIX}{}{TAP_DEVICE_SUFFIX}",
        canonical_interface_id(interface_id)
    )
}

fn open_device(interface_id: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .custom_flags(FILE_ATTRIBUTE_SYSTEM.0 | FILE_FLAG_OVERLAPPED.0)
        .open(device_path(interface_id))
        .map_err(|error| TapError::io(TapOperation::OpenDevice, error))
}

fn query_driver_version(file: &File) -> Result<WindowsTapDriverVersion> {
    let mut bytes = [0_u8; 12];
    let returned = device_control(
        file,
        TAP_IOCTL_GET_VERSION,
        None,
        Some(&mut bytes),
        TapOperation::QueryVersion,
    )?;
    require_ioctl_bytes(returned, bytes.len(), TapOperation::QueryVersion)?;
    Ok(WindowsTapDriverVersion {
        major: u32::from_ne_bytes(bytes[0..4].try_into().map_err(|_| invalid_adapter_data())?),
        minor: u32::from_ne_bytes(bytes[4..8].try_into().map_err(|_| invalid_adapter_data())?),
        debug: u32::from_ne_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| invalid_adapter_data())?,
        ) != 0,
    })
}

fn query_mac_address(file: &File) -> Result<[u8; 6]> {
    let mut mac = [0_u8; 6];
    let returned = device_control(
        file,
        TAP_IOCTL_GET_MAC,
        None,
        Some(&mut mac),
        TapOperation::QueryMac,
    )?;
    require_ioctl_bytes(returned, mac.len(), TapOperation::QueryMac)?;
    if mac == [0_u8; 6] || mac[0] & 1 != 0 {
        return Err(TapError::InvalidMacAddress);
    }
    Ok(mac)
}

fn query_driver_mtu(file: &File) -> Result<u32> {
    let mut bytes = [0_u8; 4];
    let returned = device_control(
        file,
        TAP_IOCTL_GET_MTU,
        None,
        Some(&mut bytes),
        TapOperation::QueryDriverMtu,
    )?;
    require_ioctl_bytes(returned, bytes.len(), TapOperation::QueryDriverMtu)?;
    Ok(u32::from_ne_bytes(bytes))
}

fn configure_priority_behavior(file: &File) -> Result<()> {
    let input = TAP_PRIORITY_BEHAVIOR_ENABLED.to_ne_bytes();
    device_control(
        file,
        TAP_IOCTL_PRIORITY_BEHAVIOR,
        Some(&input),
        None,
        TapOperation::ConfigurePriority,
    )?;
    Ok(())
}

fn set_media_status(file: &File, connected: bool) -> Result<()> {
    let input = u32::from(connected).to_ne_bytes();
    device_control(
        file,
        TAP_IOCTL_SET_MEDIA_STATUS,
        Some(&input),
        None,
        TapOperation::SetMediaStatus,
    )?;
    Ok(())
}

fn validate_driver_bounds(config: &TapConfig, driver_mtu: u32) -> Result<()> {
    if u32::from(config.mtu) > driver_mtu {
        return Err(TapError::DriverMtuTooSmall {
            requested: config.mtu,
            available: driver_mtu,
        });
    }
    let available_frame = driver_mtu.checked_add(TAP_VLAN_ALLOWANCE).ok_or_else(|| {
        TapError::io(
            TapOperation::QueryDriverMtu,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "driver MTU frame bound overflow",
            ),
        )
    })?;
    if u32::from(config.max_frame_size) > available_frame {
        return Err(TapError::DriverFrameTooSmall {
            requested: config.max_frame_size,
            available: available_frame,
        });
    }
    Ok(())
}

fn validate_runtime_mtu(config: &TapConfig, mtu: u16, driver_mtu: u32) -> Result<()> {
    if !(MIN_TAP_MTU..=MAX_TAP_MTU).contains(&mtu) {
        return Err(TapError::InvalidConfig {
            field: "mtu",
            reason: "must be between 576 and 9202 bytes",
        });
    }
    let minimum_frame = mtu.checked_add(14).ok_or(TapError::InvalidConfig {
        field: "maximum frame size",
        reason: "MTU plus Ethernet header overflows",
    })?;
    if minimum_frame > config.max_frame_size {
        return Err(TapError::InvalidConfig {
            field: "mtu",
            reason: "must fit the configured maximum frame size",
        });
    }
    if u32::from(mtu) > driver_mtu {
        return Err(TapError::DriverMtuTooSmall {
            requested: mtu,
            available: driver_mtu,
        });
    }
    Ok(())
}

fn update_interface_mtu(luid: NET_LUID_LH, mtu: u16) -> Result<()> {
    let mut ipv4 = query_interface_row(luid, AddressFamily::Ipv4)?;
    let mut ipv6 = query_interface_row(luid, AddressFamily::Ipv6)?;
    let old_ipv4 = ipv4.NlMtu;
    let old_ipv6 = ipv6.NlMtu;
    let requested = u32::from(mtu);

    let changed_ipv4 = old_ipv4 != requested;
    if changed_ipv4 {
        ipv4.NlMtu = requested;
        set_interface_row(
            &mut ipv4,
            AddressFamily::Ipv4,
            TapOperation::SetInterfaceMtu,
        )?;
    }
    if old_ipv6 == requested {
        return Ok(());
    }

    ipv6.NlMtu = requested;
    if let Err(update) = set_interface_row(
        &mut ipv6,
        AddressFamily::Ipv6,
        TapOperation::SetInterfaceMtu,
    ) {
        if changed_ipv4 {
            ipv4.NlMtu = old_ipv4;
            if let Err(rollback) = set_interface_row(
                &mut ipv4,
                AddressFamily::Ipv4,
                TapOperation::RollbackInterfaceMtu,
            ) {
                return Err(TapError::MtuRollbackFailed {
                    failed_family: AddressFamily::Ipv6,
                    rollback_family: AddressFamily::Ipv4,
                    update: tap_error_into_io(update),
                    rollback: tap_error_into_io(rollback),
                });
            }
        }
        return Err(update);
    }
    Ok(())
}

fn query_interface_row(luid: NET_LUID_LH, family: AddressFamily) -> Result<MIB_IPINTERFACE_ROW> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: `row` is a live writable structure of the exact API type.
    unsafe { InitializeIpInterfaceEntry(&raw mut row) };
    row.Family = windows_address_family(family);
    row.InterfaceLuid = luid;
    // SAFETY: `row` has been initialized and identifies an adapter LUID and
    // address family returned by Windows.
    let status = unsafe { GetIpInterfaceEntry(&raw mut row) };
    if status != NO_ERROR {
        return Err(TapError::InterfaceMtu {
            family,
            operation: TapOperation::QueryInterfaceMtu,
            source: win32_error_to_io(status),
        });
    }
    Ok(row)
}

fn set_interface_row(
    row: &mut MIB_IPINTERFACE_ROW,
    family: AddressFamily,
    operation: TapOperation,
) -> Result<()> {
    // SAFETY: `row` was populated by `GetIpInterfaceEntry`; only `NlMtu` was
    // changed and the pointer remains valid for the duration of the call.
    let status = unsafe { SetIpInterfaceEntry(row) };
    if status != NO_ERROR {
        return Err(TapError::InterfaceMtu {
            family,
            operation,
            source: win32_error_to_io(status),
        });
    }
    Ok(())
}

const fn windows_address_family(family: AddressFamily) -> ADDRESS_FAMILY {
    match family {
        AddressFamily::Ipv4 => AF_INET,
        AddressFamily::Ipv6 => AF_INET6,
    }
}

fn tap_error_into_io(error: TapError) -> io::Error {
    match error {
        TapError::InterfaceMtu { source, .. } | TapError::Io { source, .. } => source,
        other => io::Error::other(other),
    }
}

fn device_control(
    file: &File,
    code: u32,
    input: Option<&[u8]>,
    output: Option<&mut [u8]>,
    operation: TapOperation,
) -> Result<u32> {
    let input_pointer = input.map(|bytes| bytes.as_ptr().cast::<c_void>());
    let input_length = input
        .map_or(Ok(0_u32), |bytes| u32::try_from(bytes.len()))
        .map_err(|error| {
            TapError::io(
                operation,
                io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
    let (output_pointer, output_length) = match output {
        Some(bytes) => (
            Some(bytes.as_mut_ptr().cast::<c_void>()),
            u32::try_from(bytes.len()).map_err(|error| {
                TapError::io(
                    operation,
                    io::Error::new(io::ErrorKind::InvalidInput, error),
                )
            })?,
        ),
        None => (None, 0),
    };
    complete_overlapped(file, operation, |overlapped| {
        // SAFETY: Optional input and output pointers were derived from live
        // slices that remain borrowed until completion. Lengths match them and
        // `overlapped` remains valid until `GetOverlappedResult` returns.
        unsafe {
            DeviceIoControl(
                file_handle(file),
                code,
                input_pointer,
                input_length,
                output_pointer,
                output_length,
                None,
                Some(overlapped),
            )
        }
    })
}

fn complete_overlapped<F>(file: &File, operation: TapOperation, start: F) -> Result<u32>
where
    F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
{
    // SAFETY: Null security attributes and name request a private manual-reset
    // event. The returned handle is owned by this function.
    let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
        .map_err(|error| TapError::io(operation, windows_error_to_io(&error)))?;
    // SAFETY: `CreateEventW` returned a new owned handle that has not been
    // transferred elsewhere. `OwnedHandle` closes it exactly once.
    let _event_owner = unsafe { OwnedHandle::from_raw_handle(event.0) };
    let mut overlapped = OVERLAPPED {
        hEvent: event,
        ..OVERLAPPED::default()
    };

    match start(&raw mut overlapped) {
        Ok(()) => {}
        Err(error) if is_win32_error(&error, ERROR_IO_PENDING) => {}
        Err(error) => return Err(map_overlapped_error(operation, &error)),
    }

    let mut transferred = 0_u32;
    // SAFETY: `file` and the event remain live, and `overlapped` has not moved
    // since the operation started. Waiting completes it before any borrow ends.
    unsafe {
        GetOverlappedResult(
            file_handle(file),
            &raw const overlapped,
            &raw mut transferred,
            true,
        )
    }
    .map_err(|error| map_overlapped_error(operation, &error))?;
    Ok(transferred)
}

fn map_overlapped_error(operation: TapOperation, error: &WindowsError) -> TapError {
    if is_win32_error(error, ERROR_OPERATION_ABORTED) {
        TapError::Cancelled
    } else {
        TapError::io(operation, windows_error_to_io(error))
    }
}

fn require_ioctl_bytes(returned: u32, needed: usize, operation: TapOperation) -> Result<()> {
    let returned = usize::try_from(returned).map_err(|error| {
        TapError::io(operation, io::Error::new(io::ErrorKind::InvalidData, error))
    })?;
    if returned < needed {
        return Err(TapError::io(
            operation,
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TAP driver returned a short control response",
            ),
        ));
    }
    Ok(())
}

fn file_handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}

fn is_win32_error(error: &WindowsError, code: WIN32_ERROR) -> bool {
    error.code() == HRESULT::from_win32(code.0)
}

fn windows_error_to_io(error: &WindowsError) -> io::Error {
    let hresult = u32::from_ne_bytes(error.code().0.to_ne_bytes());
    let raw = if hresult & 0xffff_0000 == 0x8007_0000 {
        hresult & 0xffff
    } else {
        hresult
    };
    io::Error::from_raw_os_error(u32_to_i32_bits(raw))
}

fn win32_error_to_io(error: WIN32_ERROR) -> io::Error {
    io::Error::from_raw_os_error(u32_to_i32_bits(error.0))
}

const fn u32_to_i32_bits(value: u32) -> i32 {
    i32::from_ne_bytes(value.to_ne_bytes())
}

fn narrow_string(value: PSTR) -> Result<String> {
    if value.0.is_null() {
        return Err(invalid_adapter_data());
    }
    // SAFETY: `GetAdaptersAddresses` promises a valid null-terminated adapter
    // name for the lifetime of its output buffer.
    unsafe { value.to_string() }.map_err(|error| {
        TapError::io(
            TapOperation::EnumerateAdapters,
            io::Error::new(io::ErrorKind::InvalidData, error),
        )
    })
}

fn wide_string(value: PWSTR) -> Result<String> {
    if value.0.is_null() {
        return Err(invalid_adapter_data());
    }
    // SAFETY: `GetAdaptersAddresses` promises valid null-terminated UTF-16
    // strings for the lifetime of its output buffer.
    unsafe { value.to_string() }.map_err(|error| {
        TapError::io(
            TapOperation::EnumerateAdapters,
            io::Error::new(io::ErrorKind::InvalidData, error),
        )
    })
}

fn invalid_adapter_data() -> TapError {
    TapError::io(
        TapOperation::EnumerateAdapters,
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned malformed adapter metadata",
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_matches, canonical_interface_id, device_path, select_candidate, tap_control_code,
        utf16_multi_string, validate_windows_adapter_name, AdapterCandidate, WindowsTapAdapter,
        TAP_IOCTL_GET_MAC, TAP_IOCTL_GET_MTU, TAP_IOCTL_GET_VERSION, TAP_IOCTL_PRIORITY_BEHAVIOR,
        TAP_IOCTL_SET_MEDIA_STATUS,
    };
    use crate::TapError;
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    fn candidate(name: &str, id: &str) -> AdapterCandidate {
        AdapterCandidate {
            metadata: WindowsTapAdapter {
                friendly_name: name.to_string(),
                interface_id: canonical_interface_id(id),
                description: "TAP-Windows Adapter V9".to_string(),
                system_mtu: 1_500,
            },
            luid: NET_LUID_LH::default(),
        }
    }

    #[test]
    fn control_codes_match_the_public_tap_windows_abi() {
        assert_eq!(tap_control_code(1), 0x0022_0004);
        assert_eq!(TAP_IOCTL_GET_MAC, 0x0022_0004);
        assert_eq!(TAP_IOCTL_GET_VERSION, 0x0022_0008);
        assert_eq!(TAP_IOCTL_GET_MTU, 0x0022_000c);
        assert_eq!(TAP_IOCTL_SET_MEDIA_STATUS, 0x0022_0018);
        assert_eq!(TAP_IOCTL_PRIORITY_BEHAVIOR, 0x0022_002c);
    }

    #[test]
    fn selector_matches_friendly_name_or_guid_without_case_or_braces() {
        let adapter = candidate("Stella LAN", "0d8ecb8c-46f4-41fb-900b-ff82f65e9a8d");
        assert!(candidate_matches(&adapter, "stella lan"));
        assert!(candidate_matches(
            &adapter,
            "{0D8ECB8C-46F4-41FB-900B-FF82F65E9A8D}"
        ));
        assert_eq!(
            device_path(&adapter.metadata.interface_id),
            r"\\.\Global\{0D8ECB8C-46F4-41FB-900B-FF82F65E9A8D}.tap"
        );
    }

    #[test]
    fn automatic_and_explicit_selection_reject_ambiguity() {
        let adapters = vec![candidate("one", "1"), candidate("two", "2")];
        assert!(matches!(
            select_candidate(adapters.clone(), None),
            Err(TapError::AmbiguousAdapters {
                selector: None,
                count: 2,
            })
        ));
        assert!(matches!(
            select_candidate(adapters, Some("missing")),
            Err(TapError::AdapterNotFound {
                selector: Some(selector),
            }) if selector == "missing"
        ));
    }

    #[test]
    fn provisioning_names_and_hardware_ids_are_strict() {
        assert!(validate_windows_adapter_name("Stella 00112233").is_ok());
        assert!(validate_windows_adapter_name("").is_err());
        assert!(validate_windows_adapter_name(" Stella").is_err());
        assert!(validate_windows_adapter_name("Stella/TAP").is_err());
        assert!(validate_windows_adapter_name(&"x".repeat(256)).is_err());

        let encoded = utf16_multi_string("tap0901");
        let words = encoded
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect::<Vec<_>>();
        assert_eq!(words, [116, 97, 112, 48, 57, 48, 49, 0, 0]);
    }
}
