use crate::config::*;
use anyhow::Result;
use futures::future::OptionFuture;
use log::{debug, error, info, trace, warn};
use quiche::{Config, Connection, ConnectionId, Header};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use thiserror::Error;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::{net::UdpSocket, sync::oneshot};

use ring::hmac::Key;
use ring::rand::*;

struct PartialResponse {
    body: Vec<u8>,

    written: usize,
}

struct Client {
    conn: std::pin::Pin<Box<quiche::Connection>>,

    partial_responses: HashMap<u64, PartialResponse>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, (SocketAddr, Client)>;

#[derive(Error, Debug)]
#[error("Invalid URL")]
pub struct InvalidUrl;

pub struct ConnectionManager {
    tx_notify_close: oneshot::Sender<()>,
}

impl ConnectionManager {
    pub async fn listen() -> tokio::io::Result<Self> {
        // Create the UDP socket backing the QUIC connection, and register it with
        // the event loop.
        let socket = UdpSocket::bind("127.0.0.1:4433").await?;
        log::trace!("Connected to expected port");

        let clients = ClientMap::new();

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();
        let config = get_config();

        let (tx_notify_close, rx_notify_close) = oneshot::channel();

        log::trace!("Launching listening loop");
        launch_loop(clients, conn_id_seed, config, socket, rx_notify_close);
        log::trace!("Launched listening loop");

        Ok(ConnectionManager { tx_notify_close })
    }

    pub fn shutdown(self) -> Result<(), ()> {
        self.tx_notify_close.send(())
    }
}

async fn version_negotiation(
    scid: &ConnectionId<'_>,
    dcid: &ConnectionId<'_>,
    src: &std::net::SocketAddr,
    sock: &UdpSocket,
) {
    let mut out = [0; MAX_DATAGRAM_SIZE];
    warn!("Doing version negotiation");

    let len = quiche::negotiate_version(scid, dcid, &mut out).unwrap();

    let out = &out[..len];

    if let Err(err) = sock.send_to(out, &src).await {
        error!("Could not send packet: {}", err);
    }
}

async fn stateless_retry(
    hdr: &Header<'_>,
    src: &SocketAddr,
    scid: &ConnectionId<'_>,
    sock: &UdpSocket,
) {
    let mut out = [0; MAX_DATAGRAM_SIZE];

    warn!("Doing stateless retry");

    let new_token = mint_token(&hdr, &src);

    let len = quiche::retry(
        &hdr.scid,
        &hdr.dcid,
        &scid,
        &new_token,
        hdr.version,
        &mut out,
    )
    .unwrap();

    let out = &out[..len];

    if let Err(e) = sock.send_to(out, &src).await {
        error!("send() failed: {:?}", e);
    }
}

async fn get_client<'a>(
    clients: &'a mut ClientMap,
    hdr: &'a Header<'static>,
    conn_id: &'a ConnectionId<'static>,
    src: &SocketAddr,
    sock: &'a UdpSocket,
    mut config: &'a mut Config,
) -> Option<&'a mut (SocketAddr, Client)> {
    if !clients.contains_key(&hdr.dcid) && !clients.contains_key(conn_id) {
        if hdr.ty != quiche::Type::Initial {
            error!("Packet is not Initial");
            return None;
            //continue;
        }

        if !quiche::version_is_supported(hdr.version) {
            version_negotiation(&hdr.scid, &hdr.dcid, &src, &sock).await;
            return None;
            //continue;
        }

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        scid.copy_from_slice(&conn_id);

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Token is always present in Initial packets.
        let token = hdr.token.as_ref().unwrap();

        // Do stateless retry if the client didn't send a token.
        if token.is_empty() {
            stateless_retry(&hdr, &src, &scid, &sock).await;
            return None;
            //continue;
        }

        let odcid = validate_token(&src, token);

        // The token was not valid, meaning the retry failed, so
        // drop the packet.
        if odcid.is_none() {
            error!("Invalid address validation token");
            return None;
            //continue;
        }

        if scid.len() != hdr.dcid.len() {
            error!("Invalid destination connection ID");
            return None;
            //continue;
        }

        // Reuse the source connection ID we sent in the Retry packet,
        // instead of changing it again.
        let scid = hdr.dcid.clone();

        debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

        let conn = quiche::accept(&scid, odcid.as_ref(), *src, &mut config).unwrap();

        let client = Client {
            conn,
            partial_responses: HashMap::new(),
        };

        clients.insert(scid.clone(), (*src, client));

        let scid = &scid;
        clients.get_mut(scid)
    } else {
        // To appease the borrow checker god
        if clients.contains_key(&hdr.dcid) {
            clients.get_mut(&hdr.dcid)
        } else {
            clients.get_mut(&conn_id)
        }
    }
}

macro_rules! skip_none {
    ($res:expr) => {
        match $res {
            Some(val) => val,
            None => {
                continue;
            }
        }
    };
}

async fn handle_ready_client(client: &mut Client) {
    let mut buf = [0; MAX_DATAGRAM_SIZE];
    // Handle writable streams.
    for stream_id in client.conn.writable() {
        handle_writable(client, stream_id);
    }

    // Process all readable streams.
    for s in client.conn.readable() {
        while let Ok((read, fin)) = client.conn.stream_recv(s, &mut buf) {
            debug!("{} received {} bytes", client.conn.trace_id(), read);

            let stream_buf = &buf[..read];

            debug!(
                "{} stream {} has {} bytes (fin? {})",
                client.conn.trace_id(),
                s,
                stream_buf.len(),
                fin
            );

            handle_stream(client, s, stream_buf, "index.html").await;
        }
    }
}

fn get_conn_id(conn_id_seed: &Key, dest_conn_id: &[u8]) -> ConnectionId<'static> {
    let conn_id = ring::hmac::sign(conn_id_seed, dest_conn_id);
    let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
    conn_id.to_vec().into()
}

// TODO: Graceful shutdown :(
fn launch_loop(
    mut clients: ClientMap,
    conn_id_seed: Key,
    mut config: Config,
    sock: UdpSocket,
    mut rx_notify_close: oneshot::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut buf = [0; MAX_DATAGRAM_SIZE];
        let mut close = false;
        //tokio::pin!(rx_notify_close);
        while !close {
            let sleep: OptionFuture<_> = clients
                .values()
                .filter_map(|(_, c)| c.conn.timeout())
                .min()
                .map(|t| tokio::time::sleep(t))
                .into();

            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep  => {
                    clients.values_mut().for_each(|(_, c)| c.conn.on_timeout());
                }
                Ok((len, from)) = sock.recv_from(&mut buf) => {
                    debug!("got {} bytes from {}", len, from);
                    let pkt_buf = &mut buf[..len];

                    if let Ok(hdr) = quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                        trace!("got packet {:?}", hdr);

                        let conn_id = get_conn_id(&conn_id_seed, &hdr.dcid);

                        let (_, client) = skip_none!(get_client(
                            &mut clients,
                            &hdr,
                            &conn_id,
                            &from,
                            &sock,
                            &mut config,
                        ).await);

                        // Process potentially coalesced packets.
                        let recv_info = quiche::RecvInfo {from};
                        let read = match client.conn.recv(pkt_buf, recv_info) {
                            Ok(v) => v,

                            Err(e) => {
                                error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                                continue;
                            }
                        };

                        debug!("{} processed {} bytes", client.conn.trace_id(), read);

                        if client.conn.is_in_early_data() || client.conn.is_established() {
                            handle_ready_client(client).await;
                        }
                    } else {
                        error!("Got malformed pkg");
                    }
                }
                Ok(_) = &mut rx_notify_close => {
                    trace!("Closing Server");
                    close = true;
                }
            };

            write_all_clients_loop(&mut clients, &sock).await;
            collect_garbage(&mut clients);
        }
    });
}

async fn write_all_clients_loop(clients: &mut ClientMap, socket: &UdpSocket) {
    for (_, client) in clients.values_mut() {
        if let Some(err) = write_loop(&mut client.conn, socket).await.err() {
            error!("Error {} while writing", err);
        }
    }
}

async fn write_loop(conn: &mut Pin<Box<Connection>>, socket: &UdpSocket) -> tokio::io::Result<()> {
    let mut out = [0; MAX_DATAGRAM_SIZE];

    loop {
        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        let (write, info) = match conn.send(&mut out) {
            Ok(v) => v,

            Err(quiche::Error::Done) => {
                debug!("done writing");
                return Ok(());
            }

            Err(e) => {
                error!("send failed: {:?}", e);

                conn.close(false, 0x1, b"fail").ok();
                return Err(tokio::io::Error::new(
                    tokio::io::ErrorKind::Other,
                    "Quiche Error",
                ));
            }
        };

        let sent_len = socket.send_to(&out[..write], info.to).await?;
        debug!("written {}", sent_len);
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(src: &SocketAddr, token: &'a [u8]) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    let token = &token[addr.len()..];

    Some(quiche::ConnectionId::from_ref(&token[..]))
}

// TODO: Check if blocking
/// Handles newly writable streams.
fn handle_writable(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;

    debug!("{} stream {} is writable", conn.trace_id(), stream_id);

    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = client.partial_responses.get_mut(&stream_id).unwrap();
    let body = &resp.body[resp.written..];

    let written = match conn.stream_send(stream_id, &body, true) {
        Ok(v) => v,

        Err(quiche::Error::Done) => 0,

        Err(e) => {
            client.partial_responses.remove(&stream_id);

            error!("writeable {} stream send failed {:?}", conn.trace_id(), e);
            return;
        }
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
}

// TODO: This is blocking
async fn handle_stream(client: &mut Client, stream_id: u64, buf: &[u8], root: &str) {
    let conn = &mut client.conn;
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open("medium_chungus_copy")
        .await
        .unwrap();
    f.write_all(&buf).await.unwrap();

    let path = std::path::PathBuf::from(root);

    debug!("Got {:?}", buf,);

    info!(
        "{} got GET request for {:?} on stream {}",
        conn.trace_id(),
        path,
        stream_id
    );

    let body = tokio::fs::read(path.as_path())
        .await
        .unwrap_or_else(|_| b"Not Found!\r\n".to_vec());

    info!(
        "{} sending response of size {} on stream {}",
        conn.trace_id(),
        body.len(),
        stream_id
    );

    if conn.writable().any(|id| id == stream_id) {
        let written = match conn.stream_send(stream_id, &body, true) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            }
        };

        if written < body.len() {
            let response = PartialResponse { body, written };
            client.partial_responses.insert(stream_id, response);
        }
    }
}

fn collect_garbage(clients: &mut ClientMap) {
    // Garbage collect closed connections.
    clients.retain(|_, (_, ref mut c)| {
        debug!("Collecting garbage");

        if c.conn.is_closed() {
            info!(
                "{} connection collected {:?}",
                c.conn.trace_id(),
                c.conn.stats()
            );
        }

        !c.conn.is_closed()
    });
}
