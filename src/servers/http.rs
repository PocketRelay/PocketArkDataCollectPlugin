use super::redirector::create_ssl_context;
use anyhow::Context;
use hyper::{
    body::{Body, HttpBody},
    header::HOST,
    server::conn::Http,
    service::service_fn,
    Request, Response, StatusCode,
};
use log::{debug, error};
use openssl::ssl::Ssl;
use std::{convert::Infallible, net::Ipv4Addr, pin::Pin};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;

/// The local HTTP server port
pub const HTTPS_PORT: u16 = 443;

pub async fn start_server() -> anyhow::Result<()> {
    // Initializing the underlying TCP listener
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, HTTPS_PORT))
        .await
        .context("Failed to bind http listener")?;

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
                error!("Failed to serve http connection: {:?}", err);
            }
        });
    }
}

/// Handles serving an HTTP connection the provided `stream`, also
/// completes the accept stream process
pub async fn serve_connection(mut stream: SslStream<TcpStream>) -> anyhow::Result<()> {
    Pin::new(&mut stream).accept().await?;

    Http::new()
        .serve_connection(stream, service_fn(proxy_http))
        .await
        .context("Serve error")?;

    Ok(())
}

async fn proxy_http(mut req: Request<hyper::body::Body>) -> Result<Response<Body>, Infallible> {
    let req_headers = req.headers();
    let host = match req_headers.get(HOST).and_then(|value| value.to_str().ok()) {
        Some(value) => value,
        None => {
            error!("Failed to send HTTP request: Missing host");
            let mut error_response = Response::new(hyper::Body::empty());
            *error_response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(error_response);
        }
    };
    let path = req.uri().clone();
    let target_url = format!(
        "{}://{}{}",
        path.scheme_str().unwrap_or("https"),
        host,
        path.path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("")
    );

    debug!("Client HTTP request: {:?}", &req);

    let body_data = req.body_mut().data().await;
    if let Some(Ok(data)) = &body_data {
        if let Ok(value) = String::from_utf8(data.to_vec()) {
            debug!("UTF8: {}\n\n", value);
        } else {
            debug!("BINARY: {:?}", data.as_ref() as &[u8]);
        }
    }

    let client = reqwest::Client::builder()
        .default_headers(req.headers().clone())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let mut request = client.request(req.method().clone(), target_url);

    if let Some(Ok(body_data)) = body_data {
        request = request.body(body_data);
    }

    let proxy_response = request.send().await;

    let proxy_response = match proxy_response {
        Ok(value) => value,
        Err(err) => {
            error!("Failed to send HTTP request: {}", err);
            let mut error_response = Response::new(hyper::Body::empty());
            *error_response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(error_response);
        }
    };

    debug!("Server HTTP response: {:?}", &proxy_response);
    let status = proxy_response.status();
    let mut headers = proxy_response.headers().clone();

    // Remove headers that conflict with our responses
    headers.remove("transfer-encoding");
    headers.remove("content-length");

    let body = match proxy_response.bytes().await {
        Ok(value) => value,
        Err(err) => {
            error!("Failed to read HTTP response body: {}", err);
            let mut error_response = Response::new(hyper::Body::empty());
            *error_response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(error_response);
        }
    };
    if let Ok(value) = String::from_utf8(body.to_vec()) {
        debug!("UTF8: {}\n\n", value);
    } else {
        debug!("BINARY: {:?}", body.as_ref() as &[u8]);
    }

    let mut response = Response::new(hyper::body::Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;

    Ok(response)
}
