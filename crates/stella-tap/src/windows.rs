//! TAP-Windows Adapter V9 backend.

use std::{
    ffi::c_void,
    fmt,
    fs::{File, OpenOptions},
    io,
    mem::{align_of, size_of, MaybeUninit},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    sync::{Arc, Weak},
};

use windows::{
    core::{Error as WindowsError, HRESULT, PCWSTR, PSTR, PWSTR},
    Win32::{
        Foundation::{
            ERROR_BUFFER_OVERFLOW, ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_NO_DATA,
            ERROR_OPERATION_ABORTED, HANDLE, NO_ERROR, WIN32_ERROR,
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
const MINIMUM_DRIVER_MAJOR: u32 = 9;
const TAP_VLAN_ALLOWANCE: u32 = 18;

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
        let candidates = enumerate_candidates()?;
        let candidate = select_candidate(candidates, config.name.as_deref())?;
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
        AdapterCandidate, WindowsTapAdapter, TAP_IOCTL_GET_MAC, TAP_IOCTL_GET_MTU,
        TAP_IOCTL_GET_VERSION, TAP_IOCTL_PRIORITY_BEHAVIOR, TAP_IOCTL_SET_MEDIA_STATUS,
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
}
