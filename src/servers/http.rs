use crate::constants::HTTP_PORT;
use hyper::body::{Body, HttpBody};
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{server::conn::Http, Request};
use hyper::{Response, StatusCode};
use log::{debug, error};
use native_windows_gui::error_message;
use openssl::ssl::Ssl;
use reqwest::Client;
use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::pin::Pin;
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

use super::redirector::create_ssl_context;

pub async fn start_server() {
    // Initializing the underlying TCP listener
    let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, HTTP_PORT)).await {
        Ok(value) => value,
        Err(err) => {
            error_message("Failed to start http", &err.to_string());
            error!("Failed to start http: {}", err);
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

            Pin::new(&mut stream).accept().await.unwrap();

            if let Err(err) = Http::new()
                .serve_connection(stream, service_fn(proxy_http))
                .await
            {
                eprintln!("Failed to serve http connection: {:?}", err);
            }
        });
    }
}

async fn proxy_http(mut req: Request<hyper::body::Body>) -> Result<Response<Body>, Infallible> {
    let body_data = req.body_mut().data().await;
    if let Some(Ok(data)) = &body_data {
        if let Ok(value) = String::from_utf8(data.to_vec()) {
            debug!("UTF8: {}\n\n", value);
        } else {
            debug!("BINARY: {:?}", data.as_ref() as &[u8]);
        }
    }

    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_default();

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

    let target_url = format!("https://{}{}", host, path);

    debug!("Client HTTP request: {:?}", &req);

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
