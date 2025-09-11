use async_trait::async_trait;
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::sync::Arc;
use thingbuf::{mpsc, recycling};
use tracing::{error, info};

use crate::connection::Endpoint;

pub type Packet = (Vec<u8>, SocketAddr);

pub type SendQueue = thingbuf::mpsc::Sender<Packet, CustomRecycler>;
type RecvQueue = thingbuf::mpsc::Receiver<Packet, CustomRecycler>;

/// serves as abstract layer over any kind of socket or transmission api
#[async_trait]
pub trait Transmit: Send + Sync {
    /// asynchronous recv function
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;

    /// asynchronous send function
    async fn send_to(&self, buf: &[u8], to: SocketAddr) -> std::io::Result<usize>;
}

#[async_trait]
impl Transmit for tokio::net::UdpSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        self.send_to(buf, to).await
    }
}

pub trait TransmitProvider {
    type Socket: Transmit + 'static;

    fn init() -> Self;

    /// create [count] sockets bound to the given address
    fn bind(&mut self, addr: SocketAddr) -> std::io::Result<Arc<Self::Socket>>;

    /* TODO
    /// create multiple sockets bound to multiple addresses, for example for manual load-balancing
    fn bind_multiple(
        addr: Vec<SocketAddr>,
        socket_role: SocketRole,
    ) -> std::io::Result<Arc<Self::Socket>>;*/
}

/// unix-specific implementation. unix allows for binding multiple sockets to the same port.
/// In normal scenarios a single socket is sufficient but in high throughput scenarios, i.e.
/// a proxy, a multi-socket architechture benefits from the increased number of packet
/// queues in the kernel. also the kernel acts as a load-balancer in this scenario, aiming to
/// distribute packets evenly across all sockets bound to the same address.
#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use super::*;

    pub struct DefaultTransmitProvider;

    impl TransmitProvider for DefaultTransmitProvider {
        type Socket = tokio::net::UdpSocket;

        fn init() -> Self {
            DefaultTransmitProvider {}
        }

        fn bind(&mut self, addr: SocketAddr) -> std::io::Result<Arc<Self::Socket>> {
            let domain = if addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };

            let socket =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;

            socket.set_reuse_address(true)?;
            socket.set_reuse_port(true)?;
            socket.bind(&addr.into())?;

            let std_socket: std::net::UdpSocket = socket.into();
            std_socket.set_nonblocking(true)?;

            let udp = tokio::net::UdpSocket::from_std(std_socket)?;
            Ok(Arc::new(udp))
        }
    }
}

/// non-unix implementation (everything else)
#[cfg(any(target_os = "macos", windows))]
mod platform {
    use super::*;

    pub struct DefaultTransmitProvider {
        socket: Option<Arc<tokio::net::UdpSocket>>,
    }

    impl TransmitProvider for DefaultTransmitProvider {
        type Socket = tokio::net::UdpSocket;

        fn init() -> Self {
            DefaultTransmitProvider { socket: None }
        }

        /// we have to "reuse" the same socket. as noone serious will use any other os than unix-based
        /// ones for server applications, the following implementation isnt very well maintained. it
        /// basically clones the same socket by wrapping it in an [`std::net::Arc<tokio::net::UdpSocket>`].
        fn bind(&mut self, addr: SocketAddr) -> std::io::Result<Arc<Self::Socket>> {
            let socket = if self.socket.is_some() {
                self.socket.as_ref().unwrap()
            } else {
                let std_socket = std::net::UdpSocket::bind(addr)?;
                std_socket.set_nonblocking(true)?;
                &Arc::new(tokio::net::UdpSocket::from_std(std_socket)?)
            };

            Ok(socket.clone())
        }
    }
}

pub use platform::DefaultTransmitProvider;

// Reset a vector to all zeros using write_bytes (unsafe but fast). Also no size checking because
// size is not changeable during runtime
fn reset_vec_write_bytes<T: Default>(vec: &mut Vec<T>, size: usize) {
    unsafe {
        std::ptr::write_bytes(vec.as_mut_ptr(), 0, size);
        vec.set_len(size);
    }
}

#[derive(Clone, Debug)]
pub struct CustomRecycler {
    buf_size: usize,
}

impl recycling::Recycle<Packet> for CustomRecycler {
    fn new_element(&self) -> Packet {
        let v = vec![0u8; self.buf_size];
        (v, "[::1]:8080".parse().unwrap())
    }

    fn recycle(&self, element: &mut Packet) {
        reset_vec_write_bytes(&mut element.0, self.buf_size);
    }
}

// taurus uses the ringbuffer thingbuf to continously write into pre-allocated storage space. every
// socket gets a ringbuffer. The vec of senders and receivers can then be polled in parrallel.

// TODO pass vec of recv addresses and send addresses
fn start_sockets<S: TransmitProvider>(
    addr: SocketAddr,
    max_udp_payload_size: usize,
    rx_socket_queue_size: usize,
    tx_socket_queue_size: usize,
) -> (Vec<RecvQueue>, Arc<[SendQueue]>) {
    // receiving sockets
    let mut consumers = vec![];
    let rx_socket_count: usize = std::env::var("TAURUS_RX_SOCKET_COUNT")
        .ok()
        .and_then(|e| e.parse().ok())
        .unwrap_or(1);

    // transmittting sockets
    let mut transmitters = vec![];
    let tx_socket_count: usize = std::env::var("TAURUS_TX_SOCKET_COUNT")
        .ok()
        .and_then(|e| e.parse().ok())
        .unwrap_or(1);

    let mut socket_provider = S::init();

    for x in 0usize..rx_socket_count {
        // create ringbuffer with reuse policy to avoid reallocation for each packet
        let recycler = CustomRecycler {
            buf_size: max_udp_payload_size,
        };

        let (tx, rx) = mpsc::with_recycle::<Packet, CustomRecycler>(rx_socket_queue_size, recycler);

        consumers.push(rx);

        let socket = socket_provider
            .bind(addr)
            .expect("failed to bind socket to {addr}");

        tokio::spawn(async move {
            while let Ok(mut entry) = tx.send_ref().await {
                let test = &mut entry.0;
                match socket.recv_from(test).await {
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

        info!("rx socket {x}: listening on {addr}");
    }

    for x in 0usize..tx_socket_count {
        // create ringbuffer with reuse policy to avoid reallocation for each packet
        let recycler = CustomRecycler {
            buf_size: max_udp_payload_size,
        };

        let (tx, rx) = mpsc::with_recycle::<Packet, CustomRecycler>(tx_socket_queue_size, recycler);

        transmitters.push(tx);

        let socket = socket_provider
            .bind(addr)
            .expect("failed to bind socket to {addr}");

        tokio::spawn(async move {
            while let Some(entry) = rx.recv_ref().await {
                match socket.send_to(&entry.0, entry.1).await {
                    Ok(x) => {
                        info!("sent {} bytes to {}", x, entry.1);
                    }
                    Err(error) => {
                        error!("Error while sending datagram: {:?}", error);
                        continue;
                    }
                };
            }
        });

        info!("tx socket {x}: sending from {addr}");
    }

    (consumers, Arc::from(transmitters))
}

// my implmentation of a future over a Vec of receivers. Can be called in std::future::poll_fn.
// loops over all receivers and polls for readiness.
fn poll_socket_receivers<'a, T>(
    cx: &mut std::task::Context<'_>,
    rx: &'a [thingbuf::mpsc::Receiver<T, CustomRecycler>],
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

// main event loop. it reacts to three possible scenarios that require a reaction:
//  1. a packet has arrived
//  2. a timeout has occured
//  3. the application wants to send data
pub fn event_loop<S: TransmitProvider>(
    addr: SocketAddr,
    max_udp_payload_size: usize,
    rx_socket_queue_size: usize,
    tx_socket_queue_size: usize,
    mut ep: Endpoint,
) -> tokio::task::JoinHandle<usize> {
    let (rx, tx) = start_sockets::<S>(
        addr,
        max_udp_payload_size,
        rx_socket_queue_size,
        tx_socket_queue_size,
    );

    tokio::spawn(async move {
        loop {
            let recv = std::future::poll_fn(|cx| poll_socket_receivers(cx, &rx));

            let wakeup = std::future::poll_fn(|cx| ep.poll_wakeups(cx));

            tokio::select! {
                incoming = recv => {
                    if let Some(recv_buf) = incoming{
                        ep.recv(recv_buf);
                    }
                }
                _ = wakeup => {}
            }

            ep.iterate_transmission_pending(tx.clone(), |inner, sq| async move {
                if let Ok(mut sender) = sq.send_ref().await {
                    let data = sender.deref_mut();
                    let mut conn = inner.lock();

                    match conn.fetch_dgram(&mut data.0) {
                        Ok(len) => data.0.truncate(len),
                        Err(err) => error!("error while fetching datagram: {err}"),
                    }

                    data.1 = conn.get_current_path();

                    drop(conn);

                    return true;
                } else {
                    error!("failed to aquire sender ref inside io event loop");
                }
                false
            })
            .await;
        }
    })
}
