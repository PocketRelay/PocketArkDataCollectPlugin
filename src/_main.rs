#![allow(clippy::missing_safety_doc)]

use log::debug;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

use crate::servers::start_servers;

pub mod constants;
pub mod hooks;
pub mod logging;
pub mod pattern;
pub mod servers;

fn main() {
    logging::setup();

    debug!("STARTING");

    servers::components::initialize();

    // Create tokio async runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime");

    runtime.block_on(async move {
        start_servers();
        // Block for CTRL+C to keep servers alive when window closes
        _ = tokio::signal::ctrl_c().await;
    });
}
