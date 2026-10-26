use pocket_ark_client_shared::{servers::redirector, ssl::create_ssl_context};

pub mod http;
pub mod main;
pub mod packet;

pub fn start_servers() {
    tokio::spawn(async move {
        let ssl_context = create_ssl_context().expect("Failed to create ssl context");
        if let Err(err) = redirector::start_redirector_server(ssl_context).await {
            tracing::error!("Failed to start redirector server: {:?}", err);
        }
    });

    tokio::spawn(async move {
        if let Err(err) = main::start_server().await {
            tracing::error!("Failed to start main server: {:?}", err);
        }
    });

    tokio::spawn(async move {
        if let Err(err) = http::start_server().await {
            tracing::error!("Failed to start http server: {:?}", err);
        }
    });
}
