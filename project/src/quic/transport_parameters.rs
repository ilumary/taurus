use octets::{BufferTooShortError, OctetsMut};
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use crate::token;
use crate::ConnectionId;

//RFC 9000 Section 18.2
pub struct TransportConfig {
    original_destination_connection_id: Option<TransportParameter>,
    max_idle_timeout: TransportParameter,
    stateless_reset_token: Option<TransportParameter>,
    max_udp_payload_size: TransportParameter,
    initial_max_data: TransportParameter,
    initial_max_stream_data_bidi_local: TransportParameter,
    initial_max_stream_data_bidi_remote: TransportParameter,
    initial_max_stream_data_uni: TransportParameter,
    initial_max_streams_bidi: TransportParameter,
    initial_max_streams_uni: TransportParameter,
    ack_delay_exponent: TransportParameter,
    max_ack_delay: TransportParameter,
    disable_active_migration: Option<TransportParameter>,
    preferred_address: Option<PreferredAddress>,
    active_connection_id_limit: TransportParameter,
    initial_source_connection_id: Option<TransportParameter>,
    retry_source_connection_id: Option<TransportParameter>,
}

impl TransportConfig {
    pub fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: TransportParameter::new(0x0001, 0, vec![]),
            stateless_reset_token: None,
            max_udp_payload_size: TransportParameter::new(0x0003, 2, vec![255, 247]),
            initial_max_data: TransportParameter::new(0x0004, 0, vec![]),
            initial_max_stream_data_bidi_local: TransportParameter::new(0x0005, 0, vec![]),
            initial_max_stream_data_bidi_remote: TransportParameter::new(0x0006, 0, vec![]),
            initial_max_stream_data_uni: TransportParameter::new(0x0007, 0, vec![]),
            initial_max_streams_bidi: TransportParameter::new(0x0008, 0, vec![]),
            initial_max_streams_uni: TransportParameter::new(0x0009, 0, vec![]),
            ack_delay_exponent: TransportParameter::new(0x000a, 1, vec![3]),
            max_ack_delay: TransportParameter::new(0x000b, 1, vec![25]),
            disable_active_migration: Some(TransportParameter::new(0x000c, 0, vec![])),
            preferred_address: None,
            active_connection_id_limit: TransportParameter::new(0x000e, 1, vec![2]),
            initial_source_connection_id: None,
            retry_source_connection_id: None,
        }
    }

    pub fn original_destination_connection_id(&mut self, orig_dcid: &Vec<u8>) -> &mut Self {
        self.original_destination_connection_id = Some(TransportParameter::new(
            0x0000,
            orig_dcid.len() as u64,
            orig_dcid.clone(),
        ));
        self
    }

    pub fn stateless_reset_token(&mut self, token: Vec<u8>) -> &mut Self {
        self.stateless_reset_token = Some(TransportParameter::new(0x0002, 16, token));
        self
    }

    pub fn preferred_address(&mut self, address: PreferredAddress) -> &mut Self {
        self.preferred_address = Some(address);
        self
    }

    pub fn initial_source_connection_id(&mut self, initial_scid: &Vec<u8>) -> &mut Self {
        self.initial_source_connection_id = Some(TransportParameter::new(
            0x0000,
            initial_scid.len() as u64,
            initial_scid.clone(),
        ));
        self
    }

    pub fn retry_source_connection_id(&mut self, retry_scid: &Vec<u8>) -> &mut Self {
        self.retry_source_connection_id = Some(TransportParameter::new(
            0x0000,
            retry_scid.len() as u64,
            retry_scid.clone(),
        ));
        self
    }

    //TODO check if client or server, currently only server
    pub fn encode(&self, buf: &mut OctetsMut) -> Result<(), BufferTooShortError> {
        //Server only
        if let Some(tp) = &self.original_destination_connection_id {
            tp.encode(buf)?;
        }

        self.max_idle_timeout.encode(buf)?;

        //Server only
        if let Some(srt) = &self.stateless_reset_token {
            srt.encode(buf)?;
        }

        self.max_udp_payload_size.encode(buf)?;
        self.initial_max_data.encode(buf)?;
        self.initial_max_stream_data_bidi_local.encode(buf)?;
        self.initial_max_stream_data_bidi_remote.encode(buf)?;
        self.initial_max_stream_data_uni.encode(buf)?;
        self.initial_max_streams_bidi.encode(buf)?;
        self.initial_max_streams_uni.encode(buf)?;
        self.ack_delay_exponent.encode(buf)?;
        self.max_ack_delay.encode(buf)?;

        if let Some(dam) = &self.disable_active_migration {
            dam.encode(buf)?;
        }

        //Server only
        if let Some(pa) = &self.preferred_address {
            pa.encode(buf)?;
        }

        self.active_connection_id_limit.encode(buf)?;

        if let Some(initial_scid) = &self.initial_source_connection_id {
            initial_scid.encode(buf)?;
        }

        //Server only
        if let Some(retry_scid) = &self.retry_source_connection_id {
            retry_scid.encode(buf)?;
        }

        Ok(())
    }

    pub fn _read(_buf: &mut OctetsMut) {}
}

//RFC 9000 Section 18: Transport Parameter Encoding
//Id and length fields are defined as variable length integers, we store them in human
//readable form and only encode/decode if needed with Octets
pub struct TransportParameter {
    id: u64,
    length: u64,
    value: Vec<u8>,
}

impl TransportParameter {
    pub fn new(id: u64, length: u64, value: Vec<u8>) -> Self {
        Self { id, length, value }
    }

    pub fn decode(data: &mut OctetsMut<'_>) -> Result<Self, BufferTooShortError> {
        let id = data.get_varint()?;
        let length = data.get_varint()?;
        let value = data.get_bytes(length as usize).unwrap();
        Ok(Self {
            id,
            length,
            value: value.to_vec(),
        })
    }

    pub fn encode(&self, data: &mut OctetsMut<'_>) -> Result<(), BufferTooShortError> {
        data.put_varint(self.id)?;
        data.put_varint(self.length)?;
        data.put_bytes(&self.value)?;
        Ok(())
    }
}

impl fmt::Display for TransportParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:x} len:0x{:x} data:{}",
            self.id,
            self.length,
            self.value
                .iter()
                .map(|val| format!("{:x}", val))
                .collect::<Vec<String>>()
                .join(" ")
        )
    }
}

pub struct PreferredAddress {
    pub address_v4: Option<SocketAddrV4>,
    pub address_v6: Option<SocketAddrV6>,
    pub conn_id: ConnectionId,
    pub stateless_reset_token: token::StatelessResetToken,
}

impl PreferredAddress {
    pub fn len(&self) -> usize {
        let mut length: usize = 0;
        if self.address_v4.is_some() {
            length += 4 + 2;
        }
        if self.address_v6.is_some() {
            length += 16 + 2;
        }
        length += 1 + self.conn_id.len();
        length += 16;
        length
    }

    pub fn encode(&self, data: &mut OctetsMut<'_>) -> Result<(), BufferTooShortError> {
        data.put_varint(0x000d)?;
        data.put_varint(self.len() as u64)?;

        data.put_bytes(
            self.address_v4
                .map_or(Ipv4Addr::UNSPECIFIED.octets(), |a| a.ip().octets())
                .as_ref(),
        )?;
        data.put_u16(self.address_v4.map_or(0, |a| a.port()))?;

        data.put_bytes(
            self.address_v6
                .map_or(Ipv6Addr::UNSPECIFIED.octets(), |a| a.ip().octets())
                .as_ref(),
        )?;
        data.put_u16(self.address_v6.map_or(0, |a| a.port()))?;

        data.put_u8(self.conn_id.len() as u8)?;
        data.put_bytes(self.conn_id.as_slice())?;

        data.put_bytes(self.stateless_reset_token.token.as_ref())?;

        Ok(())
    }
}
