// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use log::{debug, error, info};
use quiche::{Config, Connection};
use std::io::prelude::*;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::{fs::File, time::Instant};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};
use url::Url;

use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

const HTTP_REQ_STREAM_ID: u64 = 4;

fn get_config() -> Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // *CAUTION*: this should not be set to `false` in production!!!
    config.verify_peer(false);

    config.set_application_protos(b"\x02ab").unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    config
}

async fn connect(
    url: &url::Url,
    mut out: &mut [u8],
) -> tokio::io::Result<(Pin<Box<quiche::Connection>>, UdpSocket)> {
    // Resolve server address.
    let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

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

    let write = conn.send(&mut out).expect("initial send failed");

    let _ = socket.send(&out[..write]).await?;

    debug!("written {}", write);

    Ok((conn, socket))
}

async fn read_loop(
    conn: &mut Pin<Box<Connection>>,
    socket: &UdpSocket,
    mut buf: &mut [u8],
) -> tokio::io::Result<()> {
    let len = socket.recv(&mut buf).await?;

    debug!("got {} bytes", len);

    // Process potentially coalesced packets.
    let read = conn
        .recv(&mut buf[..len])
        .map_err(|_| tokio::io::Error::new(tokio::io::ErrorKind::Other, "Quiche Error"))?;

    debug!("processed {} bytes", read);

    Ok(())
}

async fn process_streams(conn: &mut Pin<Box<Connection>>, mut buf: &mut [u8], req_start: Instant) {
    // Process all readable streams.
    for s in conn.readable() {
        while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
            debug!("received {} bytes", read);

            let stream_buf = &buf[..read];

            debug!("stream {} has {} bytes (fin? {})", s, stream_buf.len(), fin);

            print!("{}", unsafe { std::str::from_utf8_unchecked(&stream_buf) });

            // The server reported that it has no more data to send, which
            // we got the full response. Close the connection.
            if s == HTTP_REQ_STREAM_ID && fin {
                info!("response received in {:?}, closing...", req_start.elapsed());

                conn.close(true, 0x00, b"kthxbye").unwrap();
            }
        }
    }
}

/*
{
    connect().await;
    tokio::task(|| {read_packages()})
    tokio::task(|| {send_packages()})
    tokio::task(|| {setream(file)})
}
*/

async fn write_pending_packages(
    conn: &mut Pin<Box<Connection>>,
    socket: &mut UdpSocket,
    mut out: &mut [u8],
) -> tokio::io::Result<()> {
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

    socket.send(&out[..write]).await?;
    debug!("written {}", write);

    Ok(())
}

enum ConnectionMessages {
    SendMessage,
    RecievedMessage,
}

struct ConnectionManager {
    socket: UdpSocket,
    conn: Pin<Box<Connection>>,
    rx: mpsc::Receiver<ConnectionMessages>,
    tx: mpsc::Sender<ConnectionMessages>,
    send_rx: mpsc::Receiver<[u8; MAX_DATAGRAM_SIZE]>,
    send_tx: mpsc::Sender<[u8; MAX_DATAGRAM_SIZE]>,
}

impl ConnectionManager {
    async fn connect(url: Url) -> tokio::io::Result<Self> {
        let mut out = [0; MAX_DATAGRAM_SIZE];

        // Resolve server address.
        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

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

        let write = conn.send(&mut out).expect("initial send failed");

        let _ = socket.send(&out[..write]).await?;

        debug!("written {}", write);

        let (tx, rx) = mpsc::channel(32);

        let (send_tx, send_rx) = mpsc::channel(32);

        Ok(ConnectionManager {
            socket,
            conn,
            rx,
            tx,
            send_tx,
            send_rx,
        })
    }

    fn launch_process_loop(self) -> JoinHandle<()> {
        let mut rx = self.rx;
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                match message {
                    ConnectionMessages::SendMessage => {}
                    ConnectionMessages::RecievedMessage => {}
                }
            }
        })
    }

    // This is not async to not fuckup
    fn send_outstanding_packages(mut self) {
        tokio::spawn(async move {
            let mut out = [0; MAX_DATAGRAM_SIZE];
            loop {
                // Generate outgoing QUIC packets and send them on the UDP socket, until
                // quiche reports that there are no more packets to be sent.
                let write = match self.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("done writing");
                        return Ok(());
                    }

                    Err(e) => {
                        error!("send failed: {:?}", e);

                        self.conn.close(false, 0x1, b"fail").ok();
                        return Err(tokio::io::Error::new(
                            tokio::io::ErrorKind::Other,
                            "Quiche Error",
                        ));
                    }
                };

                // TODO: Will have to send size, although ideally we should send an slice to prevent
                // errors. WIll see if I handle this with a vector later as it seems safer
                self.send_tx.send(out);
            }
        });
    }

    fn launch_loop(mut self) {
        tokio::spawn(async move {
            let mut buf = [0; 65535];
            loop {
                tokio::select! {
                    Ok(len) = self.socket.recv(&mut buf) => {

                        debug!("got {} bytes", len);

                        // Process potentially coalesced packets.
                        let read = self.conn
                            .recv(&mut buf[..len])
                            .map_err(|_| tokio::io::Error::new(tokio::io::ErrorKind::Other, "Quiche Error")).expect("Please handle this :(");

                        debug!("processed {} bytes", read);
                    }
                    Some(buff) = self.send_rx.recv() => {
                        let sent_len = self.socket.send(&buff).await.expect("Please handle this too :(");
                        debug!("written {}", sent_len);
                    }
                };
            }
        });
    }
}

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    env_logger::init();

    let mut f = File::open("small_chungus")?;
    let mut file_buf = Vec::new();
    f.read_to_end(&mut file_buf)?;

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 1 {
        println!("Usage: {} URL", cmd);
        println!("\nSee tools/apps/ for more complete implementations.");
        // Lol no
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Argument Error",
        ));
    }

    let url = url::Url::parse(&args.next().unwrap()).unwrap();

    let (mut conn, mut socket) = connect(&url, &mut out).await?;

    let mut req_sent = false;
    let req_start = std::time::Instant::now();

    loop {
        read_loop(&mut conn, &socket, &mut buf).await?;

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Send an HTTP request as soon as the connection is established.
        if conn.is_established() && !req_sent {
            info!("sending HTTP request for {}", url.path());

            conn.stream_send(HTTP_REQ_STREAM_ID, &file_buf, true)
                .unwrap();

            req_sent = true;
        }

        process_streams(&mut conn, &mut buf, req_start).await;

        write_pending_packages(&mut conn, &mut socket, &mut out).await?;

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }
    }

    Ok(())
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}
