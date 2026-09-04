//! Opt-in root-only integration coverage for the macOS feth backend.

#![cfg(target_os = "macos")]

use std::{
    fs,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use stella_tap::{
    MacosTapDevice, TapCancellationHandle, TapConfig, TapDevice, TapError,
    MAX_ETHERNET_FRAME_LENGTH,
};

const IFCONFIG: &str = "/sbin/ifconfig";
const PING: &str = "/sbin/ping";
const TCPDUMP: &str = "/usr/sbin/tcpdump";
const TEST_ETHERTYPE: u16 = 0x88b5;
const LARGE_FRAME_LENGTH: usize = 4_096;

#[test]
#[ignore = "requires root and exclusive access to two temporary macOS feth interfaces"]
#[allow(clippy::too_many_lines)]
fn feth_pair_supports_lifecycle_frames_mtu_locking_and_cancellation() {
    assert_eq!(command_stdout("/usr/bin/id", &["-u"]).trim(), "0");
    let (visible, peer) = test_interface_names();
    assert_interface_absent(&visible);
    assert_interface_absent(&peer);
    let _cleanup = FethCleanup::new(visible.clone(), peer.clone());

    let config = TapConfig {
        name: Some(visible.clone()),
        peer_name: Some(peer.clone()),
        mtu: 2_000,
        max_frame_size: u16::try_from(LARGE_FRAME_LENGTH).expect("frame length fits u16"),
    };
    let mut device = MacosTapDevice::create(&config).expect("create persistent feth pair");
    assert!(matches!(
        MacosTapDevice::create(&config),
        Err(TapError::DeviceBusy { .. })
    ));
    let reversed = TapConfig {
        name: Some(peer.clone()),
        peer_name: Some(visible.clone()),
        ..config.clone()
    };
    assert!(matches!(
        MacosTapDevice::create(&reversed),
        Err(TapError::DeviceBusy { .. })
    ));

    let mac = device.mac_address().expect("query feth MAC address");
    assert_ne!(mac, [0_u8; 6]);
    assert_eq!(mac[0] & 1, 0);
    assert_eq!(interface_mac(&visible), mac);
    assert!(interface_is_up(&visible));
    let initial_mtu = interface_mtu(&visible);
    assert!(initial_mtu <= config.mtu);
    assert_eq!(interface_mtu(&peer), initial_mtu);

    let large_frame_mtu = u16::try_from(LARGE_FRAME_LENGTH - 14).expect("MTU fits u16");
    device.set_mtu(large_frame_mtu).expect("set both feth MTUs");
    assert_eq!(interface_mtu(&visible), large_frame_mtu);
    assert_eq!(interface_mtu(&peer), large_frame_mtu);

    let capture_path = std::path::Path::new("/private/tmp").join(format!(
        "stella-macos-tap-{}-large-frame.pcap",
        std::process::id()
    ));
    let _ = fs::remove_file(&capture_path);
    let _capture_cleanup = TempFileCleanup(capture_path.clone());
    let capture = start_capture(&visible, &capture_path);
    let frame = test_frame(mac, LARGE_FRAME_LENGTH);
    device
        .write_frame(&frame)
        .expect("write complete frame larger than the BPF injection ceiling");
    wait_for_success(
        capture,
        Duration::from_secs(5),
        "tcpdump large-frame capture",
    );
    let capture_summary = command_stdout(
        TCPDUMP,
        &[
            "-nn",
            "-e",
            "-r",
            capture_path.to_str().expect("UTF-8 capture path"),
            "-c",
            "1",
        ],
    );
    assert!(
        capture_summary.contains(&format!("length {LARGE_FRAME_LENGTH}:")),
        "captured frame was not complete: {capture_summary}"
    );
    fs::remove_file(&capture_path).expect("remove temporary capture");

    let cancellation = device.cancellation_handle();
    device = cancel_pending_read(device, &cancellation);
    device = read_host_arp_after_idle_cancel(device, &visible, mac);

    let closed_cancellation = device.cancellation_handle();
    device
        .destroy()
        .expect("disable visible feth and close I/O");
    closed_cancellation
        .cancel_pending_io()
        .expect("cancellation after close remains idempotent");
    assert!(interface_exists(&visible));
    assert!(interface_exists(&peer));
    assert!(!interface_is_up(&visible));

    let reopened = MacosTapDevice::create(&config).expect("reuse persistent feth pair");
    assert!(interface_is_up(&visible));
    assert_eq!(interface_mtu(&visible), config.mtu);
    assert_eq!(interface_mtu(&peer), config.mtu);
    reopened.destroy().expect("close reused feth pair");
    assert!(interface_exists(&visible));
    assert!(interface_exists(&peer));
    assert!(!interface_is_up(&visible));
}

fn cancel_pending_read(
    device: MacosTapDevice,
    cancellation: &TapCancellationHandle,
) -> MacosTapDevice {
    let (ready_sender, ready_receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut device = device;
        let mut frame = vec![0_u8; usize::from(MAX_ETHERNET_FRAME_LENGTH)];
        loop {
            ready_sender.send(()).expect("announce pending feth read");
            match device.read_frame(&mut frame) {
                Err(TapError::Cancelled) => return Ok(device),
                Ok(_) => {}
                Err(error) => return Err(error),
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !worker.is_finished() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "feth read did not become cancellable");
        match ready_receiver.recv_timeout(remaining) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("worker did not announce a pending feth read before the deadline")
            }
        }
        thread::sleep(Duration::from_millis(50));
        cancellation
            .cancel_pending_io()
            .expect("cancel pending feth read");
        cancellation
            .cancel_pending_io()
            .expect("repeat pending feth cancellation");
    }
    worker
        .join()
        .expect("pending-read worker did not panic")
        .expect("pending feth read ended by cancellation")
}

fn read_host_arp_after_idle_cancel(
    device: MacosTapDevice,
    visible: &str,
    mac: [u8; 6],
) -> MacosTapDevice {
    let cancellation = device.cancellation_handle();
    cancellation
        .cancel_pending_io()
        .expect("idle cancellation does not poison the next read");
    let host = 20 + u8::try_from(std::process::id() % 200).expect("subnet octet fits u8");
    let address = format!("10.254.{host}.1");
    let target = format!("10.254.{host}.254");
    command_success(
        IFCONFIG,
        &[visible, "inet", &address, "netmask", "255.255.255.0", "up"],
    );
    let _ = Command::new("/usr/sbin/arp")
        .args(["-d", target.as_str()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let (ready_sender, ready_receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut device = device;
        let mut frame = vec![0_u8; usize::from(MAX_ETHERNET_FRAME_LENGTH)];
        ready_sender.send(()).expect("announce ARP read");
        loop {
            let length = device.read_frame(&mut frame)?;
            if length >= 42 && frame[12..14] == [0x08, 0x06] {
                frame.truncate(length);
                return Ok::<_, TapError>((device, frame));
            }
        }
    });
    ready_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("ARP reader became ready");
    let mut ping = Command::new(PING)
        .args(["-c", "1", "-W", "1000", target.as_str()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start ping to emit an ARP request");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !worker.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if !worker.is_finished() {
        cancellation
            .cancel_pending_io()
            .expect("cancel timed-out ARP read");
        let _ = ping.kill();
        let _ = ping.wait();
        let _ = worker.join();
        panic!("timed out waiting for a host-generated ARP frame");
    }
    let _ = ping.kill();
    let _ = ping.wait();
    let (device, frame) = worker
        .join()
        .expect("ARP read worker did not panic")
        .expect("read complete host-generated ARP frame");
    assert_eq!(&frame[..6], &[0xff; 6]);
    assert_eq!(&frame[6..12], &mac);
    device
}

fn start_capture(interface: &str, path: &std::path::Path) -> Child {
    let mut child = Command::new(TCPDUMP)
        .args([
            "-i",
            interface,
            "-c",
            "1",
            "-s",
            "0",
            "-U",
            "-w",
            path.to_str().expect("UTF-8 capture path"),
            "ether",
            "proto",
            "0x88b5",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start tcpdump capture");
    thread::sleep(Duration::from_millis(500));
    assert!(
        child.try_wait().expect("poll tcpdump").is_none(),
        "tcpdump exited before frame injection"
    );
    child
}

fn wait_for_success(mut child: Child, timeout: Duration, operation: &str) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child process") {
            assert!(status.success(), "{operation} failed with {status}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{operation} timed out");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn test_frame(source: [u8; 6], length: usize) -> Vec<u8> {
    let mut frame = vec![0x5a; length];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&source);
    frame[12..14].copy_from_slice(&TEST_ETHERTYPE.to_be_bytes());
    frame
}

fn test_interface_names() -> (String, String) {
    match (
        std::env::var("STELLA_TAP_MACOS_VISIBLE").ok(),
        std::env::var("STELLA_TAP_MACOS_PEER").ok(),
    ) {
        (Some(visible), Some(peer)) => (visible, peer),
        (None, None) => {
            let base = 8_000 + (std::process::id() % 1_000) * 2;
            (format!("feth{base}"), format!("feth{}", base + 1))
        }
        _ => panic!("set both STELLA_TAP_MACOS_VISIBLE and STELLA_TAP_MACOS_PEER"),
    }
}

fn assert_interface_absent(interface: &str) {
    assert!(
        !interface_exists(interface),
        "refusing to reuse pre-existing test interface {interface}"
    );
}

fn interface_exists(interface: &str) -> bool {
    Command::new(IFCONFIG)
        .arg(interface)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn interface_description(interface: &str) -> String {
    command_stdout(IFCONFIG, &[interface])
}

fn interface_is_up(interface: &str) -> bool {
    let description = interface_description(interface);
    let flags = description
        .lines()
        .next()
        .and_then(|line| line.split_once('<'))
        .and_then(|(_, flags)| flags.split_once('>'))
        .map_or("", |(flags, _)| flags);
    flags.split(',').any(|flag| flag == "UP")
}

fn interface_mtu(interface: &str) -> u16 {
    let description = interface_description(interface);
    let words = description.split_whitespace().collect::<Vec<_>>();
    words
        .windows(2)
        .find_map(|pair| (pair[0] == "mtu").then_some(pair[1]))
        .expect("ifconfig reported MTU")
        .parse()
        .expect("parse interface MTU")
}

fn interface_mac(interface: &str) -> [u8; 6] {
    let description = interface_description(interface);
    let text = description
        .lines()
        .find_map(|line| line.trim().strip_prefix("ether "))
        .expect("ifconfig reported an Ethernet address");
    let octets = text
        .split(':')
        .map(|octet| u8::from_str_radix(octet, 16).expect("parse MAC octet"))
        .collect::<Vec<_>>();
    octets.try_into().expect("MAC has six octets")
}

fn command_success(program: &str, arguments: &[&str]) {
    let status = Command::new(program)
        .args(arguments)
        .status()
        .unwrap_or_else(|error| panic!("run {program}: {error}"));
    assert!(status.success(), "{program} failed with {status}");
}

fn command_stdout(program: &str, arguments: &[&str]) -> String {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("run {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("command output is UTF-8")
}

struct FethCleanup {
    visible: String,
    peer: String,
}

struct TempFileCleanup(std::path::PathBuf);

impl Drop for TempFileCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl FethCleanup {
    const fn new(visible: String, peer: String) -> Self {
        Self { visible, peer }
    }
}

impl Drop for FethCleanup {
    fn drop(&mut self) {
        for interface in [&self.peer, &self.visible] {
            let _ = Command::new(IFCONFIG)
                .args([interface.as_str(), "destroy"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}
