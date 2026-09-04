//! Narrow wrappers around the macOS file-descriptor and interface APIs.

use std::{
    ffi::{CStr, CString},
    io,
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr,
};

const IOC_OUT: libc::c_ulong = 0x4000_0000;
const IOC_IN: libc::c_ulong = 0x8000_0000;
const IOCPARM_MASK: libc::c_ulong = 0x1fff;

const fn ioctl_number(
    direction: libc::c_ulong,
    group: u8,
    number: u8,
    length: usize,
) -> libc::c_ulong {
    direction
        | ((length as libc::c_ulong & IOCPARM_MASK) << 16)
        | ((group as libc::c_ulong) << 8)
        | number as libc::c_ulong
}

const fn iow<T>(group: u8, number: u8) -> libc::c_ulong {
    ioctl_number(IOC_IN, group, number, size_of::<T>())
}

const fn iowr<T>(group: u8, number: u8) -> libc::c_ulong {
    ioctl_number(IOC_IN | IOC_OUT, group, number, size_of::<T>())
}

const SIOCSIFFLAGS: libc::c_ulong = iow::<libc::ifreq>(b'i', 16);
const SIOCGIFFLAGS: libc::c_ulong = iowr::<libc::ifreq>(b'i', 17);
const SIOCGIFMTU: libc::c_ulong = iowr::<libc::ifreq>(b'i', 51);
const SIOCSIFMTU: libc::c_ulong = iow::<libc::ifreq>(b'i', 52);
const SIOCIFCREATE: libc::c_ulong = iowr::<libc::ifreq>(b'i', 120);
const SIOCIFDESTROY: libc::c_ulong = iow::<libc::ifreq>(b'i', 121);
const BIOCSSEESENT: libc::c_ulong = iow::<libc::c_uint>(b'B', 119);
const DLT_EN10MB: libc::c_uint = 1;

pub(super) enum PollReady {
    Io,
    Cancelled,
}

struct InterfaceAddresses(*mut libc::ifaddrs);

impl Drop for InterfaceAddresses {
    fn drop(&mut self) {
        // SAFETY: the pointer was returned by `getifaddrs` and is freed exactly once.
        unsafe { libc::freeifaddrs(self.0) };
    }
}

pub(super) fn open_control_socket() -> io::Result<OwnedFd> {
    open_socket(libc::AF_INET, libc::SOCK_DGRAM, 0)
}

pub(super) fn open_ndrv_socket() -> io::Result<OwnedFd> {
    open_socket(libc::AF_NDRV, libc::SOCK_RAW, 0)
}

fn open_socket(
    domain: libc::c_int,
    kind: libc::c_int,
    protocol: libc::c_int,
) -> io::Result<OwnedFd> {
    // SAFETY: `socket` has no pointer arguments. A nonnegative result is an owned descriptor.
    let raw = unsafe { libc::socket(domain, kind, protocol) };
    owned_fd(raw).and_then(|fd| {
        set_cloexec(&fd)?;
        Ok(fd)
    })
}

pub(super) fn open_file(path: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: `path` is NUL-terminated and valid for the duration of the call.
    let raw = unsafe { libc::open(path.as_ptr(), flags) };
    owned_fd(raw)
}

fn owned_fd(raw: RawFd) -> io::Result<OwnedFd> {
    if raw < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a successful descriptor-returning syscall transfers ownership to this process.
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

pub(super) fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: `fd` remains open for both `fcntl` calls.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `F_SETFD` accepts an integer flag argument for this open descriptor.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: `fd` remains open for both `fcntl` calls.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `F_SETFL` accepts an integer flag argument for this open descriptor.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    // SAFETY: `descriptors` points to storage for exactly two descriptors.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `pipe` transfers ownership of both descriptors.
    let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: a successful `pipe` transfers ownership of both descriptors.
    let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    set_cloexec(&read)?;
    set_cloexec(&write)?;
    set_nonblocking(&read)?;
    set_nonblocking(&write)?;
    Ok((read, write))
}

pub(super) fn signal(fd: &OwnedFd) -> io::Result<()> {
    let byte = [1_u8];
    // SAFETY: `byte` is valid for one byte and `fd` remains open.
    let written = unsafe { libc::write(fd.as_raw_fd(), byte.as_ptr().cast(), byte.len()) };
    if written == 1 {
        return Ok(());
    }
    if written < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(());
        }
        return Err(error);
    }
    Err(io::Error::new(
        io::ErrorKind::WriteZero,
        "cancellation pipe accepted no byte",
    ))
}

pub(super) fn drain(fd: &OwnedFd) -> io::Result<()> {
    let mut bytes = [0_u8; 64];
    loop {
        // SAFETY: `bytes` is writable and `fd` remains open.
        let read = unsafe { libc::read(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if read > 0 {
            continue;
        }
        if read == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(());
        }
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(super) fn poll_interruptible(
    io_fd: &OwnedFd,
    events: libc::c_short,
    cancel_fd: &OwnedFd,
) -> io::Result<PollReady> {
    let mut descriptors = [
        libc::pollfd {
            fd: io_fd.as_raw_fd(),
            events,
            revents: 0,
        },
        libc::pollfd {
            fd: cancel_fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `descriptors` is a valid array of two `pollfd` values.
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
        if result > 0 {
            let io_ready = descriptors[0].revents & (events | libc::POLLERR | libc::POLLHUP) != 0;
            if io_ready {
                return Ok(PollReady::Io);
            }
            if descriptors[1].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
                return Ok(PollReady::Cancelled);
            }
            if descriptors
                .iter()
                .any(|descriptor| descriptor.revents & libc::POLLNVAL != 0)
            {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(super) fn read(fd: &OwnedFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buffer` is writable and `fd` remains open.
    let length = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    if length < 0 {
        Err(io::Error::last_os_error())
    } else {
        usize::try_from(length).map_err(invalid_input)
    }
}

pub(super) fn write(fd: &OwnedFd, buffer: &[u8]) -> io::Result<usize> {
    // SAFETY: `buffer` is readable and `fd` remains open.
    let length = unsafe { libc::write(fd.as_raw_fd(), buffer.as_ptr().cast(), buffer.len()) };
    if length < 0 {
        Err(io::Error::last_os_error())
    } else {
        usize::try_from(length).map_err(invalid_input)
    }
}

pub(super) fn interface_exists(name: &str) -> io::Result<bool> {
    let name = CString::new(name).map_err(invalid_input)?;
    // SAFETY: `name` is NUL-terminated.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENXIO | libc::ENOENT) | None => Ok(false),
        _ => Err(error),
    }
}

pub(super) fn create_interface(control: &OwnedFd, name: &str) -> io::Result<()> {
    let mut request = interface_request(name)?;
    ioctl_mut(control, SIOCIFCREATE, &mut request)
}

pub(super) fn destroy_interface(name: &str) -> io::Result<()> {
    let control = open_control_socket()?;
    let mut request = interface_request(name)?;
    ioctl_mut(&control, SIOCIFDESTROY, &mut request)
}

pub(super) fn interface_mtu(control: &OwnedFd, name: &str) -> io::Result<u16> {
    let mut request = interface_request(name)?;
    ioctl_mut(control, SIOCGIFMTU, &mut request)?;
    // SAFETY: SIOCGIFMTU initialized the `ifru_mtu` union member.
    let mtu = unsafe { request.ifr_ifru.ifru_mtu };
    u16::try_from(mtu).map_err(invalid_input)
}

pub(super) fn set_interface_mtu(control: &OwnedFd, name: &str, mtu: u16) -> io::Result<()> {
    let mut request = interface_request(name)?;
    request.ifr_ifru.ifru_mtu = libc::c_int::from(mtu);
    ioctl_mut(control, SIOCSIFMTU, &mut request)
}

pub(super) fn interface_flags(control: &OwnedFd, name: &str) -> io::Result<libc::c_short> {
    let mut request = interface_request(name)?;
    ioctl_mut(control, SIOCGIFFLAGS, &mut request)?;
    // SAFETY: SIOCGIFFLAGS initialized the `ifru_flags` union member.
    Ok(unsafe { request.ifr_ifru.ifru_flags })
}

pub(super) fn set_interface_flags(
    control: &OwnedFd,
    name: &str,
    flags: libc::c_short,
) -> io::Result<()> {
    let mut request = interface_request(name)?;
    request.ifr_ifru.ifru_flags = flags;
    ioctl_mut(control, SIOCSIFFLAGS, &mut request)
}

pub(super) fn set_interface_up(control: &OwnedFd, name: &str, up: bool) -> io::Result<()> {
    let flags = interface_flags(control, name)?;
    let up_flags =
        libc::c_short::try_from(libc::IFF_UP | libc::IFF_RUNNING).map_err(invalid_input)?;
    let up_flag = libc::c_short::try_from(libc::IFF_UP).map_err(invalid_input)?;
    let next = if up {
        flags | up_flags
    } else {
        flags & !up_flag
    };
    set_interface_flags(control, name, next)
}

pub(super) fn interface_mac(name: &str) -> io::Result<[u8; 6]> {
    let requested = CString::new(name).map_err(invalid_input)?;
    let mut head = ptr::null_mut();
    // SAFETY: `head` points to storage for the returned linked-list head.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = InterfaceAddresses(head);
    let mut current = head;
    while !current.is_null() {
        // SAFETY: nodes in the `getifaddrs` list remain valid until `freeifaddrs`.
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null()
            // SAFETY: `ifa_name` is a NUL-terminated string owned by the list.
            && unsafe { CStr::from_ptr(entry.ifa_name) } == requested.as_c_str()
            && !entry.ifa_addr.is_null()
            // SAFETY: every sockaddr begins with the length and family bytes.
            && unsafe { libc::c_int::from((*entry.ifa_addr).sa_family) } == libc::AF_LINK
        {
            // SAFETY: AF_LINK entries point to `sockaddr_dl` values.
            let link = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_dl>() };
            if usize::from(link.sdl_alen) == 6 {
                let offset = usize::from(link.sdl_nlen);
                let end = offset.checked_add(6).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "link-layer address overflow")
                })?;
                if end <= link.sdl_data.len() {
                    let mut address = [0_u8; 6];
                    for (output, input) in address.iter_mut().zip(&link.sdl_data[offset..end]) {
                        *output = input.to_ne_bytes()[0];
                    }
                    return Ok(address);
                }
            }
        }
        current = entry.ifa_next;
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "interface has no Ethernet address",
    ))
}

pub(super) fn bind_ndrv(fd: &OwnedFd, name: &str) -> io::Result<()> {
    let bytes = name.as_bytes();
    let mut address = libc::sockaddr_ndrv {
        snd_len: u8::try_from(size_of::<libc::sockaddr_ndrv>()).map_err(invalid_input)?,
        snd_family: u8::try_from(libc::AF_NDRV).map_err(invalid_input)?,
        snd_name: [0; libc::IFNAMSIZ],
    };
    if bytes.len() >= address.snd_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name is too long for AF_NDRV",
        ));
    }
    address.snd_name[..bytes.len()].copy_from_slice(bytes);
    let length =
        libc::socklen_t::try_from(size_of::<libc::sockaddr_ndrv>()).map_err(invalid_input)?;
    let pointer = (&raw const address).cast::<libc::sockaddr>();
    // SAFETY: `pointer` refers to a fully initialized `sockaddr_ndrv` of `length` bytes.
    if unsafe { libc::bind(fd.as_raw_fd(), pointer, length) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the same valid sockaddr is used to connect the already-bound socket.
    if unsafe { libc::connect(fd.as_raw_fd(), pointer, length) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn configure_bpf(
    fd: &OwnedFd,
    name: &str,
    requested_buffer: usize,
) -> io::Result<usize> {
    let mut buffer_length = libc::c_uint::try_from(requested_buffer).map_err(invalid_input)?;
    ioctl_mut(fd, libc::BIOCSBLEN, &mut buffer_length)?;
    let mut enabled: libc::c_uint = 1;
    let mut disabled: libc::c_uint = 0;
    ioctl_mut(fd, libc::BIOCIMMEDIATE, &mut enabled)?;
    ioctl_mut(fd, BIOCSSEESENT, &mut disabled)?;
    let mut request = interface_request(name)?;
    ioctl_mut(fd, libc::BIOCSETIF, &mut request)?;
    ioctl_mut(fd, libc::BIOCSHDRCMPLT, &mut enabled)?;
    ioctl_no_arg(fd, libc::c_ulong::from(libc::BIOCPROMISC))?;
    let mut data_link: libc::c_uint = 0;
    ioctl_mut(fd, libc::BIOCGDLT, &mut data_link)?;
    if data_link != DLT_EN10MB {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "BPF interface does not expose Ethernet frames",
        ));
    }
    ioctl_no_arg(fd, libc::c_ulong::from(libc::BIOCFLUSH))?;
    Ok(buffer_length as usize)
}

fn interface_request(name: &str) -> io::Result<libc::ifreq> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name length",
        ));
    }
    // SAFETY: all-zero is a valid initial state for `ifreq` before selecting a union member.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (target, source) in request.ifr_name.iter_mut().zip(bytes) {
        *target = libc::c_char::from_ne_bytes([*source]);
    }
    Ok(request)
}

fn ioctl_mut<T>(fd: &OwnedFd, request: libc::c_ulong, value: &mut T) -> io::Result<()> {
    // SAFETY: the request determines a pointer to `T`; every caller supplies the SDK-matching type.
    if unsafe { libc::ioctl(fd.as_raw_fd(), request, value) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn ioctl_no_arg(fd: &OwnedFd, request: libc::c_ulong) -> io::Result<()> {
    // SAFETY: these BPF requests are declared with `_IO` and take no third argument.
    if unsafe { libc::ioctl(fd.as_raw_fd(), request) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn invalid_input(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{iow, iowr};

    #[test]
    fn sdk_ioctl_numbers_match_darwin_abi() {
        assert_eq!(iowr::<libc::ifreq>(b'i', 120), 0xc020_6978);
        assert_eq!(iow::<libc::ifreq>(b'i', 121), 0x8020_6979);
        assert_eq!(iow::<libc::c_uint>(b'B', 119), 0x8004_4277);
    }
}
