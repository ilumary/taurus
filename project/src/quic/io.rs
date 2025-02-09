use nix::sys::socket::{setsockopt, sockopt};
use parking_lot::Mutex;
use std::net::UdpSocket as StdUdpSocket;
use std::ops::DerefMut;
use std::{net::SocketAddr, sync::Arc};
use thingbuf::mpsc::{Receiver, Sender};
use thingbuf::{mpsc, recycling};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::connection::{Endpoint, LockedInner};
use crate::{packet, terror, ConnectionId, Inner, InnerEvent};

type Packet = (Vec<u8>, SocketAddr);

#[derive(Clone, Debug)]
struct CustomRecycler {
    buf_size: usize,
}

impl recycling::Recycle<Packet> for CustomRecycler {
    fn new_element(&self) -> Packet {
        (
            Vec::with_capacity(self.buf_size),
            "[::1]:8080".parse().unwrap(),
        )
    }

    fn recycle(&self, element: &mut Packet) {
        element.0.clear();
        element.0.shrink_to(self.buf_size);
    }
}

pub async fn start_sockets(
    addr: &str,
    max_udp_payload_size: usize,
    rx_socket_queue_size: usize,
    tx_socket_queue_size: usize,
) {
    // receiving sockets
    let mut consumers = vec![];
    let rx_socket_count: usize = std::env::var("TAURUS_RX_SOCKET_COUNT")
        .ok()
        .and_then(|e| e.parse().ok())
        .unwrap_or(1);

    for x in 0usize..rx_socket_count {
        // create ringbuffer with reuse policy to avoid reallocation for each packet
        let recycler = CustomRecycler {
            buf_size: max_udp_payload_size,
        };

        let (tx, rx) = mpsc::with_recycle::<Packet, CustomRecycler>(rx_socket_queue_size, recycler);

        consumers.push(rx);

        // create socket with reused port, unix only
        let socket = StdUdpSocket::bind(addr).expect("fatal error: socket bind failed");
        setsockopt(&socket, sockopt::ReusePort, &true);
        socket.set_nonblocking(true);
        let async_socket =
            UdpSocket::from_std(socket).expect("fatal error: async socket create failed");

        tokio::spawn(async move {
            while let Ok(mut entry) = tx.send_ref().await {
                match async_socket.recv_from(&mut entry.0).await {
                    Ok((size, src_addr)) => {
                        entry.0.truncate(size);
                        entry.1 = src_addr;
                    }
                    Err(error) => {
                        error!("Error while receiving datagram: {:?}", error);
                        continue;
                    }
                };
            }
        });

        info!("socket {x}: listening on {addr}");
    }

    // transmittting sockets
    let mut transmitters = vec![];
    let tx_socket_count: usize = std::env::var("TAURUS_TX_SOCKET_COUNT")
        .ok()
        .and_then(|e| e.parse().ok())
        .unwrap_or(1);

    for x in 0usize..tx_socket_count {
        // create ringbuffer with reuse policy to avoid reallocation for each packet
        let recycler = CustomRecycler {
            buf_size: max_udp_payload_size,
        };

        let (tx, rx) = mpsc::with_recycle::<Packet, CustomRecycler>(tx_socket_queue_size, recycler);

        transmitters.push(tx);

        // create socket with reused port, unix only
        let socket = StdUdpSocket::bind(addr).expect("fatal error: socket bind failed");
        setsockopt(&socket, sockopt::ReusePort, &true);
        socket.set_nonblocking(true);
        let async_socket =
            UdpSocket::from_std(socket).expect("fatal error: async socket create failed");

        tokio::spawn(async move {
            while let Some(mut entry) = rx.recv_ref().await {
                let addr = entry.1.clone();
                match async_socket.send_to(&mut entry.0, addr).await {
                    Ok(x) => {
                        info!("sent {} bytes to {}", x, entry.1);
                    }
                    Err(error) => {
                        error!("Error while receiving datagram: {:?}", error);
                        continue;
                    }
                };
            }
        });

        info!("socket {x}: sending from {addr}");
    }

    let jh = io_event_loop(consumers, transmitters);
}

// my implmentation of a future over a Vec of receivers. Can be called in std::future::poll_fn.
// loops over all receivers and polls for readiness.
fn poll_socket_receivers<'a, T>(
    cx: &mut std::task::Context<'_>,
    rx: &'a [Receiver<T, CustomRecycler>],
) -> std::task::Poll<Option<thingbuf::mpsc::RecvRef<'a, T>>> {
    for rx_ch in rx {
        match rx_ch.poll_recv_ref(cx) {
            std::task::Poll::Ready(Some(rr)) => {
                return std::task::Poll::Ready(Some(rr));
            }
            std::task::Poll::Ready(None) => {
                return std::task::Poll::Ready(None);
            }
            std::task::Poll::Pending => {
                continue;
            }
        }
    }
    std::task::Poll::Pending
}

fn get_available_sender<'a>(
    senders: &'a [Sender<Packet, CustomRecycler>],
) -> Option<&'a Sender<Packet, CustomRecycler>> {
    senders.iter().find(|s| s.remaining() > 0)
}

pub async fn io_event_loop(
    rx: Vec<Receiver<Packet, CustomRecycler>>,
    tx: Vec<Sender<Packet, CustomRecycler>>,
) -> tokio::task::JoinHandle<usize> {
    tokio::spawn(async move {
        loop {
            let rr = std::future::poll_fn(|cx| poll_socket_receivers(cx, &rx)).await;

            if let Some(mut packet) = rr {
                let data = packet.deref_mut();
            } else {
                error!("failed to aquire recv ref inside io event loop");
                return 0usize;
            }

            if let Some(s) = get_available_sender(&tx) {
                if let Ok(mut sender) = s.send_ref().await {
                    let data = sender.deref_mut();
                } else {
                    error!("failed to aquire sender ref inside io event loop");
                    return 0usize;
                }
            }
        }
    })
}

//starts the main event loop over a socket. Receive new packet, decode dcid, match to connnection,
//if no connnection was found initialize a new one
/*pub async fn start(mut endpoint: Endpoint, address: SocketAddr) -> Result<(), terror::Error> {
    let socket = UdpSocket::bind(address)
        .await
        .expect("fatal error: socket bind failed");

    info!("listening on {}", address);

    tokio::spawn(async move {
        loop {
            let mut buffer: Vec<u8> = vec![0u8; u16::MAX as usize];

            let (size, src_addr) = match socket.recv_from(&mut buffer).await {
                Ok((size, src_addr)) => (size, src_addr),
                Err(error) => {
                    println!("Error while receiving datagram: {:?}", error);
                    continue;
                }
            };

            let head = match &buffer[0] >> 7 {
                0x01 => "LH",
                0x00 => "SH",
                _ => "NOT RECOGNISED",
            };

            info!("Received {:?} bytes from {:?} ({})", size, src_addr, head);

            let dcid = match packet::Header::get_dcid(&buffer, 8) {
                Ok(h) => h,
                Err(error) => {
                    error!("error while retrieving dcid from packet: {}", error);
                    continue;
                }
            };

            debug!("searching for {}", &dcid);
            let mut answer = [0u8; 65536];
            let answer_size: usize;
            let mut dst_addr: SocketAddr = src_addr;

            //match incoming packet to connection
            if let Some(handle) = endpoint.connections.get(&dcid) {
                debug!("found existing connection");
                let mut transmit_ready: Option<Arc<LockedInner>> = None;

                {
                    let mut c = handle.0.lock();
                    if let Err(error) = c.recv(&mut buffer[..size], src_addr) {
                        //TODO match error.kind() for transport error
                        error!("error processing datagram: {}", error);
                        match error.kind() {
                            0x00 => (),
                            0x01..=0x10 => {
                                todo!("send connection close frame");
                            }
                            _ => {
                                todo!("probably nothing idk i'll have to find out at some point");
                            }
                        }
                    }

                    //poll for events in connection with outside effect
                    while let Some(event) = c.poll_event() {
                        match event {
                            InnerEvent::ConnectionEstablished => {
                                transmit_ready = Some(handle.clone())
                            }
                            InnerEvent::NewConnectionId(_ncid) => {
                                todo!("new cid insertion not yet implemented");
                            }
                        }
                    }

                    //prepare answer
                    answer_size = match c.fetch_dgram(&mut answer) {
                        Ok(s) => s,
                        Err(err) => {
                            error!("failed to fetch datagram: {}", err);
                            continue;
                        }
                    };

                    dst_addr = c.remote;
                }

                //transmit ready after guard is dropped
                if let Some(c) = transmit_ready {
                    if let Err(error) = endpoint
                        .new_connection_tx
                        .send(crate::Connection { api: c })
                        .await
                    {
                        error!("error while providing new connection: {}", error);
                    }
                }
            } else if ((buffer[0] & packet::LS_TYPE_BIT) >> 7) == 1
                && ((buffer[0] & packet::LONG_PACKET_TYPE) >> 4) == 0
            {
                let (inner, cid, asize) = match handle_new_connection(
                    &mut buffer,
                    &mut answer,
                    src_addr,
                    endpoint.server_config.clone(),
                    &endpoint.hmac_reset_key,
                ) {
                    Ok((i, c, s)) => (i, c, s),
                    Err(e) => {
                        // if we encounter an error within the initial packet, the connection is
                        // immediately abandoned
                        error!("encountered error while accepting new connection: {}", e);
                        todo!("handle error in case initial packet fails");
                    }
                };

                answer_size = asize;

                //push connection into lookupmap using the provided cid
                endpoint
                    .connections
                    .insert(cid, Arc::new(LockedInner(Mutex::new(inner))));
            } else {
                warn!("received unknown packet");
                continue;
            }

            //send data back
            let size = match socket.send_to(&answer[..answer_size], dst_addr).await {
                Ok(size) => size,
                Err(error) => {
                    error!("{}", terror::Error::socket_error(format!("{}", error)));
                    continue;
                }
            };

            info!("sent {} bytes to {}", size, dst_addr);
        }
    });

    Ok(())
}*/

fn handle_new_connection(
    buffer: &mut Vec<u8>,
    answer: &mut [u8],
    src_addr: SocketAddr,
    server_config: Option<Arc<rustls::ServerConfig>>,
    hmac_reset_key: &ring::hmac::Key,
) -> Result<(Inner, ConnectionId, usize), terror::Error> {
    let server_config = server_config.unwrap();

    let (mut inner, cid) =
        Inner::accept(buffer, src_addr.to_string(), server_config, hmac_reset_key)?;

    let size = inner.fetch_dgram(answer)?;

    Ok((inner, cid, size))
}
