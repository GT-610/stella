//! Stella client binary entry point.

#![forbid(unsafe_code)]

mod cli;

use std::{io::Write, process::ExitCode};

fn main() -> ExitCode {
    match cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut stderr = std::io::stderr().lock();
            let _write_result = writeln!(stderr, "error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
