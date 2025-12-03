use anyhow::Context;
use hyper::{
    body::Body,
    header::{HeaderValue, CONTENT_TYPE},
    server::conn::Http,
    service::service_fn,
    HeaderMap, Request, Response, StatusCode,
};

use log::error;
use openssl::{
    pkey::PKey,
    rsa::Rsa,
    ssl::{Ssl, SslContext, SslMethod, SslVersion},
    x509::X509,
};
use std::{convert::Infallible, net::Ipv4Addr, pin::Pin};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;

use super::main::MAIN_PORT;

/// The local redirector server port
pub const REDIRECTOR_PORT: u16 = 42230;

/// winter15.gosredirector.ea.com
pub async fn start_server() -> anyhow::Result<()> {
    // Initializing the underlying TCP listener
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, REDIRECTOR_PORT))
        .await
        .context("Failed to bind listener")?;

    // Create SSL context
    let ctx = create_ssl_context().context("Failed to setup ssl context")?;

    // Accept incoming connections
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("Failed to accept connection")?;

        let ssl = Ssl::new(&ctx).context("Failed to get ssl instance")?;
        let stream = SslStream::new(ssl, stream).context("Failed to create ssl stream")?;

        tokio::task::spawn(async move {
            if let Err(err) = serve_connection(stream).await {
                error!("Failed to serve redirector connection: {:?}", err);
            }
        });
    }
}

/// Handles serving an HTTP connection the provided `stream`, also
/// completes the accept stream process
pub async fn serve_connection(mut stream: SslStream<TcpStream>) -> anyhow::Result<()> {
    Pin::new(&mut stream).accept().await?;

    Http::new()
        .serve_connection(stream, service_fn(handle_redirect))
        .await
        .context("Serve error")?;

    Ok(())
}

/// Creates the SSL context for the redirector to use
pub fn create_ssl_context() -> anyhow::Result<SslContext> {
    const CERTIFICATE_BYTES: &[u8] = include_bytes!("../../certs/winter15.crt");
    const PRIVATE_KEY_BYTES: &[u8] = include_bytes!("../../certs/winter15.key");

    let certificate = X509::from_pem(CERTIFICATE_BYTES).context("Failed to load certificate")?;
    let private_key =
        Rsa::private_key_from_pem(PRIVATE_KEY_BYTES).context("Failed to load private key")?;
    let private_key = PKey::from_rsa(private_key).context("Failed to create private key")?;

    let mut builder =
        SslContext::builder(SslMethod::tls_server()).context("Failed to create ssl context")?;

    // Set the certificate and private key
    builder.set_certificate(&certificate)?;
    builder.set_private_key(&private_key)?;

    // Ensure the server uses TLSv1.2
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;

    Ok(builder.build())
}

async fn handle_redirect(req: Request<hyper::body::Body>) -> Result<Response<Body>, Infallible> {
    // Handle unexpected requests
    if req.uri().path() != "/redirector/getServerInstance" {
        let mut response = Response::new(hyper::body::Body::empty());
        *response.status_mut() = StatusCode::NOT_FOUND;
        return Ok(response);
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

    let mut headers = HeaderMap::new();
    headers.insert("X-BLAZE-COMPONENT", HeaderValue::from_static("redirector"));
    headers.insert(
        "X-BLAZE-COMMAND",
        HeaderValue::from_static("getServerInstance"),
    );
    headers.insert("X-BLAZE-SEQNO", HeaderValue::from_static("0"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));

    let mut response = Response::new(hyper::body::Body::from(body));
    *response.headers_mut() = headers;

    Ok(response)
}
