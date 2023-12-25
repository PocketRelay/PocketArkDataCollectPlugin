use super::packet::Packet;
use crate::servers::packet::{PacketCodec, PacketDebug};
use anyhow::{anyhow, Context};
use futures_util::{SinkExt, StreamExt};
use hyper::header::CONTENT_TYPE;
use log::{debug, error};
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
    pin::Pin,
};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
};
use tokio_openssl::SslStream;
use tokio_util::codec::Framed;

/// The local proxy main server port
pub const MAIN_PORT: u16 = 42128;

/// Starts the main server proxy. This creates a connection to the Pocket Relay
/// which is upgraded and then used as the main connection fro the game.
pub async fn start_server() -> anyhow::Result<()> {
    // Initializing the underlying TCP listener
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, MAIN_PORT))
        .await
        .context("Failed to bind listener")?;

    // Obtain address of official servers
    let official_addr = get_official_server_addr()
        .await
        .context("Failed to find official server address")?;

    // Accept incoming connections
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("Failed to accept connection")?;

        debug!("Main connection ->");

        // Spawn off a new handler for the connection
        _ = tokio::spawn(handle_blaze(stream, official_addr)).await;
    }
}

/// Creates the SSL context used by clients when connecting to the
/// official server
fn create_ssl_context() -> anyhow::Result<SslContext> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;

    builder.set_verify(SslVerifyMode::NONE);
    builder.set_security_level(0);

    Ok(builder.build())
}

/// Creates and connects a stream with the official server
async fn connect_server(official_addr: SocketAddr) -> anyhow::Result<SslStream<TcpStream>> {
    let context = create_ssl_context()?;
    let ssl = Ssl::new(&context)?;
    let stream = TcpStream::connect(official_addr).await?;
    let mut stream = SslStream::new(ssl, stream)?;

    Pin::new(&mut stream).connect().await?;

    Ok(stream)
}

async fn handle_blaze(client: TcpStream, official_addr: SocketAddr) {
    let server = match connect_server(official_addr).await {
        Ok(value) => value,
        Err(err) => {
            error!("Failed to obtain session with official server: {}", err);
            return;
        }
    };

    let mut client_framed = Framed::new(client, PacketCodec);
    let mut server_framed = Framed::new(server, PacketCodec);

    // TODO: Expand this into a proper future that doesn't block when sending
    loop {
        select! {
            packet = client_framed.next() => {
                if let Some(Ok(packet)) = packet {
                    debug_log_packet(&packet, "Send");
                    _= server_framed.send(packet).await;
                }
            }
            packet = server_framed.next() => {
                if let Some(Ok(packet)) = packet {
                    debug_log_packet(&packet, "Receive");
                    _ = client_framed.send(packet).await;
                }
            }
        }
    }
}

fn debug_log_packet(packet: &Packet, action: &str) {
    let debug = PacketDebug { packet };
    debug!("\nOfficial: {}\n{:?}", action, debug);
}

#[derive(Deserialize)]
pub struct RedirectorResponse {
    pub address: InstanceAddr,
}

#[derive(Deserialize)]
pub struct InstanceAddr {
    pub valu: AddrValu,
}

#[derive(Deserialize)]
pub struct AddrValu {
    #[serde(rename = "hostname")]
    pub host_name: String,
    pub ip: u32,
    pub port: u16,
}

/// The official redirector URL
const REDIRECTOR_URL: &str =
    "https://winter15.gosredirector.ea.com:42230/redirector/getServerInstance";
/// The request payload for requesting the server instance
const REDIRECTOR_PAYLOAD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
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

/// Attempts to obtain the [SocketAddr] of an official server instance
/// using the winter15 redirector service
pub async fn get_official_server_addr() -> anyhow::Result<SocketAddr> {
    // Create a trusting client to request the server details
    let client = reqwest::Client::builder()
        .use_native_tls()
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true)
        .build()
        .context("Failed to create HTTP client")?;
    // Request a server from the redirector
    let response = client
        .post(REDIRECTOR_URL)
        .header(CONTENT_TYPE, "application/xml")
        .body(REDIRECTOR_PAYLOAD)
        .send()
        .await?;
    // Get an parse the response
    let text = response.text().await?;
    let body: RedirectorResponse = quick_xml::de::from_str(&text)?;

    let AddrValu {
        host_name, port, ..
    } = body.address.valu;

    let mut address = (host_name, port).to_socket_addrs()?;
    let address = address
        .next()
        .ok_or(anyhow!("Failed to get socket address of official server"))?;

    debug!("Obtained official instance: {}", &address);

    Ok(address)
}
