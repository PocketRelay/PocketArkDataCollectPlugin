use tokio::join;

pub mod components;
pub mod http;
pub mod main;
pub mod packet;
pub mod redirector;
pub mod retriever;

pub fn start_servers() {
    tokio::spawn(async move {
        join!(
            main::start_server(),
            redirector::start_server(),
            // Redirector
            http::start_server(42230),
            // Pin River
            http::start_server(443),
            // Certs
            http::start_server(44325)
        );
    });
}
