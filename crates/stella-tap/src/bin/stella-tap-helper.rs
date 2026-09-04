//! Foreground privileged helper for the macOS Stella TAP backend.

#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use std::{env, io::Write, path::PathBuf, process::ExitCode};

    use stella_tap::{run_macos_tap_helper, MacosTapHelperConfig, DEFAULT_MACOS_HELPER_SOCKET};

    fn usage() -> &'static str {
        "Usage: stella-tap-helper --allow-uid UID [--socket ABSOLUTE_PATH]"
    }

    fn parse() -> Result<MacosTapHelperConfig, String> {
        let mut arguments = env::args().skip(1);
        let mut allowed_uid = None;
        let mut socket_path = PathBuf::from(DEFAULT_MACOS_HELPER_SOCKET);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--allow-uid" => {
                    let value = arguments
                        .next()
                        .ok_or_else(|| "--allow-uid requires a value".to_owned())?;
                    allowed_uid = Some(
                        value
                            .parse::<u32>()
                            .map_err(|_| "--allow-uid must be an unsigned integer".to_owned())?,
                    );
                }
                "--socket" => {
                    socket_path = PathBuf::from(
                        arguments
                            .next()
                            .ok_or_else(|| "--socket requires a value".to_owned())?,
                    );
                }
                "-h" | "--help" => return Err(usage().to_owned()),
                _ => return Err(format!("unknown argument {argument:?}")),
            }
        }
        let allowed_uid = allowed_uid.ok_or_else(|| "--allow-uid is required".to_owned())?;
        Ok(MacosTapHelperConfig::new(socket_path, allowed_uid))
    }

    let config = match parse() {
        Ok(config) => config,
        Err(message) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "{message}\n{}", usage());
            return ExitCode::from(2);
        }
    };
    match run_macos_tap_helper(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("stella-tap-helper is supported only on macOS");
    std::process::ExitCode::FAILURE
}
