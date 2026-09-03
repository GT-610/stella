#![cfg(target_os = "windows")]

//! Opt-in integration coverage for an installed TAP-Windows Adapter V9.

use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use stella_tap::{TapConfig, TapDevice, TapError, WindowsTapDevice, DEFAULT_MAX_FRAME_SIZE};

#[test]
#[ignore = "requires exclusive access to an installed TAP-Windows Adapter V9"]
fn installed_adapter_supports_lifecycle_frame_write_and_cancellation() {
    let selector = std::env::var("STELLA_TAP_WINDOWS_ADAPTER")
        .expect("set STELLA_TAP_WINDOWS_ADAPTER to a TAP-Windows connection name or GUID");
    let adapters = WindowsTapDevice::installed_adapters().expect("enumerate TAP-Windows adapters");
    let adapter = adapters
        .iter()
        .find(|adapter| {
            adapter.friendly_name.eq_ignore_ascii_case(&selector)
                || adapter.interface_id.eq_ignore_ascii_case(&selector)
        })
        .expect("selected TAP-Windows adapter is installed");
    let mtu = u16::try_from(adapter.system_mtu).expect("installed adapter MTU fits u16");
    assert!((576..=9_202).contains(&mtu));

    let config = TapConfig {
        name: Some(selector),
        mtu,
        max_frame_size: DEFAULT_MAX_FRAME_SIZE.max(mtu + 14),
    };
    let mut device =
        WindowsTapDevice::create(&config).expect("open configured TAP-Windows adapter");
    assert!(device.driver_version().major >= 9);
    assert!(device.driver_mtu() >= u32::from(mtu));
    let mac = device.mac_address().expect("query cached TAP MAC");
    assert_ne!(mac, [0_u8; 6]);
    assert_eq!(mac[0] & 1, 0);
    device
        .set_mtu(mtu)
        .expect("idempotently apply existing MTU");

    let frame = test_frame(mac);
    device
        .write_frame(&frame)
        .expect("write one complete experimental Ethernet frame");

    let cancellation = device.cancellation_handle();
    let (ready_tx, ready_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut device = device;
        let mut output = vec![0_u8; usize::from(DEFAULT_MAX_FRAME_SIZE)];
        loop {
            ready_tx.send(()).expect("announce pending-read attempt");
            match device.read_frame(&mut output) {
                Err(TapError::Cancelled) => return Ok(device),
                Ok(_) => {}
                Err(error) => return Err(error),
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "TAP read did not become cancellable");
        match ready_rx.recv_timeout(remaining) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("worker did not announce a cancellable read before the deadline")
            }
        }
        thread::sleep(Duration::from_millis(50));
        cancellation
            .cancel_pending_io()
            .expect("cancel pending overlapped TAP I/O");
        if worker.is_finished() {
            break;
        }
    }

    let device = worker
        .join()
        .expect("TAP worker did not panic")
        .expect("pending TAP read ended only by cancellation");
    device
        .destroy()
        .expect("restore media-disconnected state and close TAP device");
    cancellation
        .cancel_pending_io()
        .expect("post-close cancellation remains idempotent");
}

fn test_frame(source: [u8; 6]) -> [u8; 60] {
    let mut frame = [0_u8; 60];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&source);
    frame[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
    frame[14..].fill(0x5a);
    frame
}
