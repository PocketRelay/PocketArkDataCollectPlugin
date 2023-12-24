use anyhow::anyhow;
use futures_util::{SinkExt, StreamExt};
use hyper::header::CONTENT_TYPE;
use log::{debug, error};
use openssl::ssl::{Ssl, SslConnector, SslMethod};
use reqwest;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, net::Ipv4Addr, pin::Pin};
use tdf::{DecodeError, GroupSlice, TdfDeserialize, TdfDeserializeOwned, TdfSerialize, TdfTyped};
use thiserror::Error;
use tokio::{io, net::TcpStream};
use tokio_openssl::SslStream;
use tokio_util::codec::Framed;

use crate::servers::{components::redirector, packet::PacketDebug};

use super::packet::{FireFrame2, FrameFlags, Packet, PacketCodec};

mod response {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct Response {
        pub address: Address,
    }

    #[derive(Deserialize)]
    pub struct Address {
        pub valu: Valu,
    }

    #[derive(Deserialize)]
    pub struct Valu {
        pub host_name: String,
        pub ip: u32,
        pub port: u16,
    }
}

/// Connection details for an official server instance
pub struct OfficialInstance {
    /// The host address of the official server
    pub host: String,
    /// The port of the official server.
    pub port: u16,
}

impl OfficialInstance {
    const REDIRECTOR_HOST: &str = "winter15.gosredirector.ea.com";
    const REDIRECT_PORT: u16 = 42230;

    pub async fn obtain() -> anyhow::Result<OfficialInstance> {
        let host = Self::lookup_host().await?;
        debug!("Completed host lookup: {}", &host);

        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
    <serverinstancerequest>
      <blazesdkversion>15.1.1.3.0</blazesdkversion>
      <blazesdkbuilddate>Feb  5 2017 13:00:04</blazesdkbuilddate>
      <clientname>Contact</clientname>
      <clienttype>CLIENT_TYPE_GAMEPLAY_USER</clienttype>
      <clientplatform>pc</clientplatform>
      <clientskuid>301449</clientskuid>
      <clientversion>Future739583retail-x64-0001-60</clientversion>       
      <dirtysdkversion>15.1.2.1.0</dirtysdkversion>
      <environment>prod</environment>
      <clientlocale>1701727834</clientlocale>
      <name>masseffect-4-pc</name>
      <platform>Windows</platform>
      <connectionprofile>standardSecure_v4</connectionprofile>
      <istrial>0</istrial>
    </serverinstancerequest>"#;

        let redirector_url = format!(
            "https://{}:{}/redirector/getServerInstance",
            host,
            Self::REDIRECT_PORT
        );

        let client = reqwest::Client::new();
        let response = client
            .post(redirector_url)
            .header(CONTENT_TYPE, "application/xml")
            .body(body)
            .send()
            .await?;
        let text = response.text().await?;

        let body: response::Response = quick_xml::de::from_str(&text)?;

        let host = body.address.valu.host_name;
        let port = body.address.valu.port;

        debug!(
            "Retriever instance obtained. (Host: {} Port: {})",
            &host, port
        );

        Ok(OfficialInstance { host, port })
    }

    async fn lookup_host() -> anyhow::Result<String> {
        let host = Self::REDIRECTOR_HOST;

        // Attempt to lookup using the system DNS
        {
            let tokio = tokio::net::lookup_host(host)
                .await
                .ok()
                .and_then(|mut value| value.next());

            if let Some(tokio) = tokio {
                let ip = tokio.ip();
                // Loopback value means it was probbably redirected in the hosts file
                // so those are ignored
                if !ip.is_loopback() {
                    return Ok(format!("{}", ip));
                }
            }
        }

        // Attempt to lookup using cloudflares DNS over HTTP

        let client = reqwest::Client::new();
        let url = format!("https://cloudflare-dns.com/dns-query?name={host}&type=A");
        let mut response: LookupResponse = client
            .get(url)
            .header("Accept", "application/dns-json")
            .send()
            .await?
            .json()
            .await?;

        let data = response
            .answer
            .pop()
            .map(|value| value.data)
            .ok_or(anyhow!("Missing lookup data"))?;
        Ok(data)
    }

    /// Creates a stream to the main server and wraps it with a
    /// session returning that session. Will return None if the
    /// stream failed.
    pub async fn stream(&self) -> anyhow::Result<SslStream<TcpStream>> {
        let connector = SslConnector::builder(SslMethod::tls_client())?.build();
        let context = connector.into_context();

        let ssl = Ssl::new(&context)?;
        let stream = TcpStream::connect((self.host.as_str(), self.port)).await?;
        let mut stream = SslStream::new(ssl, stream)?;

        Pin::new(&mut stream).connect().await?;

        Ok(stream)
    }
}

/// Logs the contents of the provided packet to the debug output along with
/// the header information.
///
/// `component` The component for the packet routing
/// `packet`    The packet that is being logged
/// `direction` The direction name for the packet
fn debug_log_packet(packet: &Packet, action: &str) {
    let debug = PacketDebug { packet };
    debug!("\nOfficial: {}\n{:?}", action, debug);
}

/// Structure for the lookup responses from the google DNS API
///
/// # Structure
///
/// ```
/// {
///   "Status": 0,
///   "TC": false,
///   "RD": true,
///   "RA": true,
///   "AD": false,
///   "CD": false,
///   "Question": [
///     {
///       "name": "gosredirector.ea.com.",
///       "type": 1
///     }
///   ],
///   "Answer": [
///     {
///       "name": "gosredirector.ea.com.",
///       "type": 1,
///       "TTL": 300,
///       "data": "159.153.64.175"
///     }
///   ],
///   "Comment": "Response from 2600:1403:a::43."
/// }
/// ```
#[derive(Deserialize)]
struct LookupResponse {
    #[serde(rename = "Answer")]
    answer: Vec<Answer>,
}

/// Structure for answer portion of request. Only the data value is
/// being used so only that is present here.
///
/// # Structure
/// ```
/// {
///   "name": "gosredirector.ea.com.",
///   "type": 1,
///   "TTL": 300,
///   "data": "159.153.64.175"
/// }
/// ```
#[derive(Deserialize)]
struct Answer {
    data: String,
}
