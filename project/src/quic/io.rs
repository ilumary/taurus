use std::{net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::Mutex};
use tracing::{debug, error, info, warn};

use crate::{
    packet, terror, ConnectionId, ConnectionState, Endpoint, Inner, InnerEvent, LockedInner,
};

//starts the main event loop over a socket. Receive new packet, decode dcid, match to connnection,
//if no connnection was found initialize a new one
pub async fn start(mut endpoint: Endpoint, address: SocketAddr) -> Result<(), terror::Error> {
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
                let mut c = handle.0.lock().await;
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
                for event in c.poll_events() {
                    match event {
                        InnerEvent::ConnectionEstablished => {
                            if let Err(error) = endpoint
                                .new_connection_tx
                                .send(crate::Connection {
                                    api: handle.clone(),
                                })
                                .await
                            {
                                error!("error while providing new connection: {}", error);
                            }
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
                drop(c);
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
}

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

    //promote connection state
    inner.state = ConnectionState::Handshake;

    Ok((inner, cid, size))
}
