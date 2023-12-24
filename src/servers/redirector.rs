use crate::constants::{MAIN_PORT, REDIRECTOR_PORT};
use hyper::body::Body;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{server::conn::Http, Request};
use hyper::{HeaderMap, Response, StatusCode};
use log::error;
use native_windows_gui::error_message;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVersion};
use openssl::x509::X509;

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::pin::Pin;
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

/// winter15.gosredirector.ea.com
pub async fn start_server() {
    // Initializing the underlying TCP listener
    let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, REDIRECTOR_PORT)).await {
        Ok(value) => value,
        Err(err) => {
            error_message("Failed to start redirector", &err.to_string());
            error!("Failed to start redirector: {}", err);
            return;
        }
    };

    let ctx = create_ssl_context();

    // Accept incoming connections
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(value) => value,
            Err(_) => break,
        };

        let ssl = Ssl::new(&ctx).unwrap();

        tokio::task::spawn(async move {
            let mut stream = SslStream::new(ssl, stream).unwrap();

            Pin::new(&mut stream).accept().await;

            if let Err(err) = Http::new()
                .serve_connection(stream, service_fn(handle_redirect))
                .await
            {
                eprintln!("Failed to serve http connection: {:?}", err);
            }
        });
    }
}

/// Creates the SSL context for the redirector to use
pub fn create_ssl_context() -> SslContext {
    let crt = X509::from_der(include_bytes!("cert.der")).unwrap();
    let pkey = PKey::from_rsa(Rsa::private_key_from_pem(include_bytes!("server.key.pem")).unwrap())
        .unwrap();

    let mut builder = SslContext::builder(SslMethod::tls_server()).unwrap();
    builder.set_certificate(&crt).unwrap();
    builder.set_private_key(&pkey).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();

    builder.build()
}

async fn handle_redirect(req: Request<hyper::body::Body>) -> Result<Response<Body>, Infallible> {
    if req.uri().path() != "/redirector/getServerInstance" {
        let mut response = Response::new(hyper::body::Body::empty());
        *response.status_mut() = StatusCode::NOT_FOUND;
    }

    let ip = u32::from_be_bytes([127, 0, 0, 1]);
    let port = MAIN_PORT;

    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
    <serverinstanceinfo>
        <address member="0">
            <valu>
                <hostname>localhost</hostname>
                <ip>{ip}</ip>
                <port>{port}</port>
            </valu>
        </address>
        <secure>0</secure>
        <trialservicename></trialservicename>
        <defaultdnsaddress>0</defaultdnsaddress>
    </serverinstanceinfo>"#
    );

    let headers: HeaderMap = [
        (
            HeaderName::from_static("X-BLAZE-COMPONENT"),
            HeaderValue::from_static("redirector"),
        ),
        (
            HeaderName::from_static("X-BLAZE-COMMAND"),
            HeaderValue::from_static("getServerInstance"),
        ),
        (
            HeaderName::from_static("X-BLAZE-SEQNO"),
            HeaderValue::from_static("0"),
        ),
        (
            HeaderName::from_static("Content-Type"),
            HeaderValue::from_static("application/xml"),
        ),
    ]
    .into_iter()
    .collect();

    let mut response = Response::new(hyper::body::Body::from(body));
    *response.headers_mut() = headers;

    Ok(response)
}
