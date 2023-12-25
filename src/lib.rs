#![allow(clippy::missing_safety_doc)]

use crate::servers::start_servers;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

pub mod hooks;
pub mod logging;
pub mod servers;

/// Constant storing the application version
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
unsafe extern "system" fn DllMain(dll_module: usize, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        logging::setup();

        // Applies the host lookup hook
        unsafe { hooks::hook_host_lookup() };

        // Spawn UI and prepare task set
        std::thread::spawn(|| {
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
        });
    }

    true
}
