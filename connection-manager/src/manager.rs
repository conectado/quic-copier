use crate::config::*;
use anyhow::Result;
use futures::future::OptionFuture;
use log::{debug, error, info, trace};
use quiche::Connection;
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, net::ToSocketAddrs};
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};
use url::Url;

use ring::rand::*;

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}

pub struct ConnectionManager {
    tx: mpsc::Sender<(Vec<u8>, u64)>,
    txs: Mutex<HashMap<u64, oneshot::Sender<Vec<u8>>>>,
    rx_notify_close: oneshot::Receiver<()>,
}

#[derive(Error, Debug)]
#[error("Invalid URL")]
pub struct InvalidUrl;

impl ConnectionManager {
    pub async fn connect(url: Url) -> Result<Arc<Self>> {
        let mut out = [0; MAX_DATAGRAM_SIZE];

        // Resolve server address.
        let peer_addr = url.to_socket_addrs()?.next().ok_or(InvalidUrl)?;

        // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
        // server address. This is needed on macOS and BSD variants that don't
        // support binding to IN6ADDR_ANY for both v4 and v6.
        let bind_addr = match peer_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };

        // Create the UDP socket backing the QUIC connection, and register it with
        // the event loop.
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(peer_addr).await?;

        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();

        let mut config = get_config();

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(None, &scid, peer_addr, &mut config).unwrap();

        info!(
            "connecting to {:} from {:} with scid {}",
            peer_addr,
            socket.local_addr().unwrap(),
            hex_dump(&scid)
        );

        let (write, send_info) = conn.send(&mut out)?;

        let _ = socket.send_to(&out[..write], send_info.to).await?;

        debug!("written {}", write);

        let (tx, rx) = mpsc::channel(32);

        let (tx_notify_close, rx_notify_close) = oneshot::channel();

        let connection_manager = Arc::new(ConnectionManager {
            tx: tx.clone(),
            rx_notify_close,
            txs: Default::default(),
        });

        connection_manager
            .clone()
            .launch_loop(socket, conn, rx, tx, tx_notify_close);

        Ok(connection_manager)
    }

    pub async fn close(self) {}

    pub async fn send(&self, what: Vec<u8>, stream_id: u64) -> anyhow::Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        match self.txs.lock().expect("Mutex panic").entry(stream_id) {
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(anyhow::anyhow!("Stream Id in use"))
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(tx);
            }
        }
        if let Err(_) = self.tx.send((what, stream_id)).await {
            // I refuse to clone `what` to display it as an error message
            debug!("Can't send message Loop already closed or too many messages enqueded");
        }

        Ok(rx.await.unwrap())
    }

    async fn write_loop(
        conn: &mut Pin<Box<Connection>>,
        socket: &UdpSocket,
    ) -> tokio::io::Result<()> {
        let mut out = [0; MAX_DATAGRAM_SIZE];

        loop {
            // Generate outgoing QUIC packets and send them on the UDP socket, until
            // quiche reports that there are no more packets to be sent.
            let (write, send_info) = match conn.send(&mut out) {
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

            let sent_len = socket.send_to(&out[..write], send_info.to).await?;
            debug!("written {}", sent_len);
        }
    }

    fn return_responses(
        self: &Arc<Self>,
        fin: bool,
        stream_id: u64,
        partial_reponses: &mut HashMap<u64, Vec<u8>>,
    ) -> bool {
        if fin {
            if let Some(tx) = self.txs.lock().expect("Mutex panic").remove(&stream_id) {
                if let Err(err) = tx.send(partial_reponses.remove(&stream_id).unwrap().to_vec()) {
                    error!("Stopped listening to send response too early, {:?}", err);
                }
                return true;
            }
        }
        false
    }

    fn process_streams(
        self: &Arc<Self>,
        conn: &mut Pin<Box<Connection>>,
        mut buf: &mut [u8],
        partial_reponses: &mut HashMap<u64, Vec<u8>>,
        finalized_streams: &mut HashSet<u64>,
    ) {
        // Process all readable streams.
        for s in conn.readable() {
            debug!("Current capacity: {:?}", conn.stream_capacity(s));
            while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                debug!("received {} bytes", read);

                let stream_buf = &buf[..read];

                debug!("stream {} has {} bytes (fin? {})", s, stream_buf.len(), fin);

                print!("{}", unsafe { std::str::from_utf8_unchecked(&stream_buf) });
                partial_reponses.entry(s).or_default().extend(stream_buf);

                let mut response_sent = false;
                if finalized_streams.contains(&s) {
                    response_sent = self.return_responses(fin, s, partial_reponses);
                }

                if response_sent {
                    finalized_streams.remove(&s);
                }
            }
        }
    }

    fn launch_loop(
        self: Arc<Self>,
        sock: UdpSocket,
        mut conn: Pin<Box<Connection>>,
        mut rx: mpsc::Receiver<(Vec<u8>, u64)>,
        tx: mpsc::Sender<(Vec<u8>, u64)>,
        tx_notify_close: oneshot::Sender<()>,
    ) {
        tokio::spawn(async move {
            let mut buf = [0; MAX_DATAGRAM_SIZE];
            let mut queued_messages = Some(Vec::new());
            let mut partial_reponses = Default::default();
            let mut finalized_streams = HashSet::new();
            loop {
                let sleep: OptionFuture<_> = conn.timeout().map(|t| tokio::time::sleep(t)).into();
                tokio::pin!(sleep);
                tokio::select! {
                    _ = &mut sleep => {
                        conn.on_timeout();
                    }
                    Ok((len, from)) = sock.recv_from(&mut buf) => {
                        debug!("got {} bytes from {}", len, from);
                        let was_established = conn.is_established();
                        // Process potentially coalesced packets.
                        let recv_info = quiche::RecvInfo {from};
                        let _ = match conn.recv(&mut buf[..len], recv_info) {
                                Err(e) => debug!("{} The connection will be closed", e),
                                _ => {}
                        };

                        self.process_streams(&mut conn, &mut buf, &mut partial_reponses, &mut finalized_streams);

                        if !was_established && conn.is_established() {
                            trace!("Connection established to send packages");
                            let tx = tx.clone();
                            let queued_messages = queued_messages.take().expect("Connection should get established only once");
                            tokio::spawn(async move {
                                for m in queued_messages {
                                    tx.send(m).await.expect("Reciever shouldn't be dropped while the loop is running");
                                }
                            });
                        }

                    }
                    Some((what, stream_id)) = rx.recv() => {
                        let mut what = what;
                        if conn.is_established() || conn.is_in_early_data() {
                            trace!("Trying to send {:?} bytes", what.len());
                            let sent_len = conn
                                .stream_send(stream_id, &what, true)
                                .unwrap();
                            what.drain(..sent_len);
                            let tx = tx.clone();
                            if what.len() > 0 {
                                tokio::spawn(async move {
                                    tx.send((what, stream_id)).await.expect("Reciever dropped while sending message");
                                });
                            } else {
                                finalized_streams.insert(stream_id);
                            }

                            trace!("Will send {:?} bytes", sent_len);
                        } else {
                            queued_messages.as_mut().expect("Should be Some if connection isn't established").push((what, stream_id));
                            info!("Connection is not yet ready to send packages");
                        }
                    }
                };

                Self::write_loop(&mut conn, &sock)
                    .await
                    .expect("Socket closed");

                finalized_streams.retain(|s| {
                    !self.return_responses(conn.stream_finished(*s), *s, &mut partial_reponses)
                });

                // Should extract the repeated logic for checking connection is closed
                if conn.is_closed() {
                    debug!("connection closed");
                    if let Err(_) = tx_notify_close.send(()) {
                        error!("No one waiting for close");
                    }
                    break;
                }
            }
        });
    }
}
