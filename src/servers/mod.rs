use log::error;
use native_windows_gui::error_message;

pub mod components;
pub mod http;
pub mod main;
pub mod packet;
pub mod redirector;

pub fn start_servers() {
    tokio::spawn(async move {
        if let Err(err) = redirector::start_server().await {
            error_message("Failed to start redirector server", &err.to_string());
            error!("Failed to start redirector server: {:?}", err);
        }
    });

    tokio::spawn(async move {
        if let Err(err) = main::start_server().await {
            error_message("Failed to start main server", &err.to_string());
            error!("Failed to start main server: {:?}", err);
        }
    });

    tokio::spawn(async move {
        if let Err(err) = http::start_server().await {
            error_message("Failed to start http server", &err.to_string());
            error!("Failed to start http server: {:?}", err);
        }
    });
}
