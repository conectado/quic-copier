use crate::config::*;
use anyhow::Result;
use log::{debug, error, info};
use quiche::Connection;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};
use url::Url;

use ring::rand::*;

const HTTP_REQ_STREAM_ID: u64 = 4;

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}

pub struct ConnectionManager {
    tx: mpsc::Sender<Vec<u8>>,
    rx_notify_close: oneshot::Receiver<tokio::io::Result<()>>,
}

#[derive(Error, Debug)]
#[error("Invalid URL")]
pub struct InvalidUrl;

impl ConnectionManager {
    pub async fn connect(url: Url) -> Result<Self> {
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
        let mut conn = quiche::connect(url.domain(), &scid, &mut config).unwrap();

        info!(
            "connecting to {:} from {:} with scid {}",
            peer_addr,
            socket.local_addr().unwrap(),
            hex_dump(&scid)
        );

        let write = conn.send(&mut out)?;

        let _ = socket.send(&out[..write]).await?;

        debug!("written {}", write);

        let (tx, rx) = mpsc::channel(32);

        let (tx_notify_close, rx_notify_close) = oneshot::channel();

        launch_loop(socket, conn, rx, tx.clone(), tx_notify_close);

        Ok(ConnectionManager {
            tx,
            rx_notify_close,
        })
    }

    // TODO: self moves for now, but might want to re-think this since we might need to do
    // different things the manager in the future
    pub async fn send(self, what: Vec<u8>) -> tokio::io::Result<()> {
        if let Err(_) = self.tx.send(what).await {
            // I refuse to clone `what` to display it as an error message
            debug!("Can't send message Loop already closed or too many messages enqueded");
        }

        self.rx_notify_close
            .await
            .expect("Loop shouldn't be closed without notifying")?;

        Ok(())
    }
}

async fn write_loop(conn: &mut Pin<Box<Connection>>, socket: &UdpSocket) -> tokio::io::Result<()> {
    let mut out = [0; MAX_DATAGRAM_SIZE];

    loop {
        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        let write = match conn.send(&mut out) {
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

        let sent_len = socket.send(&out[..write]).await?;
        debug!("written {}", sent_len);
    }
}

fn process_streams(conn: &mut Pin<Box<Connection>>, mut buf: &mut [u8]) {
    // Process all readable streams.
    for s in conn.readable() {
        debug!("Current capacity: {:?}", conn.stream_capacity(s));
        while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
            debug!("received {} bytes", read);

            let stream_buf = &buf[..read];

            debug!("stream {} has {} bytes (fin? {})", s, stream_buf.len(), fin);

            print!("{}", unsafe { std::str::from_utf8_unchecked(&stream_buf) });

            /*
            if s == HTTP_REQ_STREAM_ID && fin {
                debug!("closing connection...");

                conn.close(true, 0x00, b"kthxbye").unwrap();
            }
            */
        }
    }
}

fn notify_close(
    write_result: tokio::io::Result<()>,
    tx_notify_close: &mut Option<oneshot::Sender<tokio::io::Result<()>>>,
) {
    if let Err(_) = tx_notify_close
        .take()
        .expect("Connection should be closed only once")
        .send(write_result)
    {
        debug!("Reciever dropped for close notification");
    }
}

fn launch_loop(
    sock: UdpSocket,
    mut conn: Pin<Box<Connection>>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    tx_notify_close: oneshot::Sender<tokio::io::Result<()>>,
) {
    let mut tx_notify_close = Some(tx_notify_close);
    let mut ready = true;
    tokio::spawn(async move {
        let mut buf = [0; 65535];
        let mut queued_messages = Some(Vec::new());
        let mut write_result = Ok(());
        loop {
            let timeout = match conn.timeout() {
                Some(t) => t,
                None => {
                    debug!("Timer disarmed");
                    notify_close(write_result, &mut tx_notify_close);

                    break;
                }
            };

            let sleep = tokio::time::sleep(timeout);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep => {
                    conn.on_timeout();
                }
                Ok(len) = sock.recv(&mut buf) => {
                    debug!("got {} bytes", len);
                    let was_established = conn.is_established();
                    // Process potentially coalesced packets.
                    let _ = match conn.recv(&mut buf[..len]) {
                            Err(e) => debug!("{} The connection will be closed", e),
                            _ => {}
                    };

                    process_streams(&mut conn, &mut buf);
                    ready = true;

                    if !was_established && conn.is_established() {
                        let tx = tx.clone();
                        let queued_messages = queued_messages.take().expect("Connection should get established only once");
                        tokio::spawn(async move {
                            for m in queued_messages {
                                tx.send(m).await.expect("Reciever shouldn't be dropped while the loop is running");
                            }
                        });
                    }

                }
                // TODO: Stop using channels, and move this to a method
                Some(what) = rx.recv(), if ready => {
                    let mut what = what;
                    if conn.is_established() {
                        info!("Trying to send {:?} bytes", what.len());
                        let sent_len = conn
                            .stream_send(HTTP_REQ_STREAM_ID, &what, true)
                            .unwrap();
                        what.drain(..sent_len);
                        ready = false;
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            tx.send(what).await.expect("Reciever dropped while sending message");
                        });

                        info!("Will send {:?} bytes", sent_len);
                    } else {
                        queued_messages.as_mut().expect("Should be Some if connection isn't established").push(what);
                    }
                }
            };

            let was_closed = conn.is_closed();
            write_result = write_loop(&mut conn, &sock).await;
            // Should extract the repeated logic for checking connection is closed
            if !was_closed && conn.is_closed() {
                debug!("connection closed");
                notify_close(write_result, &mut tx_notify_close);
                break;
            }
        }
    });
}
