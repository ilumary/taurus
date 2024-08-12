use core::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use octets::{Octets, OctetsMut};

use crate::{terror, token::StatelessResetToken, ConnectionId, MAX_CID_SIZE};

trait IOHandler<T> {
    fn encode(value: &T, buf: &mut OctetsMut) -> Result<(), octets::BufferTooShortError>;
    fn decode(buf: &mut Octets) -> Result<T, octets::BufferTooShortError>;
}

impl IOHandler<ConnectionId> for ConnectionId {
    fn encode(
        value: &ConnectionId,
        buf: &mut OctetsMut,
    ) -> Result<(), octets::BufferTooShortError> {
        buf.put_varint(value.len() as u64)?;
        buf.put_bytes(&value.id)?;
        Ok(())
    }

    fn decode(buf: &mut Octets) -> Result<ConnectionId, octets::BufferTooShortError> {
        let length = buf.get_varint()?;
        Ok(ConnectionId::from_vec(
            buf.get_bytes(length.try_into().unwrap())?.to_vec(),
        ))
    }
}

#[derive(PartialEq, Default)]
pub struct VarInt {
    value: u64,
}

impl VarInt {
    pub fn get(&self) -> u64 {
        self.value
    }
}

impl From<u64> for VarInt {
    fn from(x: u64) -> VarInt {
        VarInt { value: x }
    }
}

impl IOHandler<VarInt> for VarInt {
    fn encode(value: &VarInt, buf: &mut OctetsMut) -> Result<(), octets::BufferTooShortError> {
        let length = crate::packet::varint_length(value.value) as u64;
        println!(
            "encoding {:x?} with length field {:x?}",
            value.value, length
        );
        buf.put_varint(length)?;
        buf.put_varint(value.value)?;
        Ok(())
    }

    fn decode(buf: &mut Octets) -> Result<VarInt, octets::BufferTooShortError> {
        let _ = buf.get_varint()?;
        Ok(Self {
            value: buf.get_varint()?,
        })
    }
}

impl IOHandler<StatelessResetToken> for StatelessResetToken {
    fn encode(
        token: &StatelessResetToken,
        buf: &mut OctetsMut,
    ) -> Result<(), octets::BufferTooShortError> {
        //stateless_reset_token is always 16 bytes long
        buf.put_varint(0x10)?;
        buf.put_bytes(&token.token)?;
        Ok(())
    }

    fn decode(buf: &mut Octets) -> Result<StatelessResetToken, octets::BufferTooShortError> {
        let length = buf.get_varint()?;
        if length == 16 {
            return Ok(StatelessResetToken::from(
                buf.get_bytes(length.try_into().unwrap())?.to_vec(),
            ));
        }
        Err(octets::BufferTooShortError)
    }
}

#[derive(PartialEq, Default)]
pub struct PreferredAddressData {
    pub address_v4: Option<SocketAddrV4>,
    pub address_v6: Option<SocketAddrV6>,
    pub conn_id: ConnectionId,
    pub stateless_reset_token: StatelessResetToken,
}

impl PreferredAddressData {
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
}

impl IOHandler<PreferredAddressData> for PreferredAddressData {
    fn decode(_buf: &mut Octets) -> Result<PreferredAddressData, octets::BufferTooShortError> {
        todo!()
    }

    fn encode(
        pa: &PreferredAddressData,
        buf: &mut OctetsMut,
    ) -> Result<(), octets::BufferTooShortError> {
        buf.put_varint(0x000d)?;
        buf.put_varint(pa.len() as u64)?;

        buf.put_bytes(
            pa.address_v4
                .map_or(Ipv4Addr::UNSPECIFIED.octets(), |a| a.ip().octets())
                .as_ref(),
        )?;
        buf.put_u16(pa.address_v4.map_or(0, |a| a.port()))?;

        buf.put_bytes(
            pa.address_v6
                .map_or(Ipv6Addr::UNSPECIFIED.octets(), |a| a.ip().octets())
                .as_ref(),
        )?;
        buf.put_u16(pa.address_v6.map_or(0, |a| a.port()))?;

        buf.put_u8(pa.conn_id.len() as u8)?;
        buf.put_bytes(pa.conn_id.as_slice())?;

        buf.put_bytes(pa.stateless_reset_token.token.as_ref())?;

        Ok(())
    }
}

trait TransportParameter: Sized {
    const ID: usize;

    type ValueType;

    fn get_value(&self) -> Option<&Self::ValueType>;

    fn decode(buf: &mut Octets) -> Result<Self, terror::Error>;

    fn encode(&self, buf: &mut OctetsMut) -> Result<(), terror::Error>;
}

macro_rules! transport_parameter {
    ($name:ident, $id:expr, $valuetype:ty) => {
        transport_parameter!($name, $id, $valuetype, <$valuetype as Default>::default());
    };
    ($name:ident, $id:expr, $valuetype:ty, $default:expr) => {
        pub struct $name {
            value: $valuetype,
        }

        impl $name {
            //Expose get method so that trait can be private
            pub fn get(&self) -> Option<&$valuetype> {
                self.get_value()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self { value: $default }
            }
        }

        impl TryFrom<$valuetype> for $name {
            type Error = terror::Error;

            fn try_from(value: $valuetype) -> Result<Self, Self::Error> {
                Self { value }.validate()
            }
        }

        impl TransportParameter for $name {
            const ID: usize = $id;

            type ValueType = $valuetype;

            fn get_value(&self) -> Option<&Self::ValueType> {
                Some(&self.value)
            }

            fn decode(buf: &mut Octets) -> Result<Self, terror::Error> {
                Self {
                    value: <Self::ValueType as IOHandler<Self::ValueType>>::decode(buf)
                        .map_err(|e| terror::Error::buffer_size_error(format!("{}", e)))?,
                }
                .validate()
            }

            fn encode(&self, buf: &mut OctetsMut) -> Result<(), terror::Error> {
                if self.value != $default {
                    buf.put_varint(Self::ID as u64)
                        .map_err(|e| terror::Error::buffer_size_error(format!("{}", e)))?;

                    <Self::ValueType as IOHandler<Self::ValueType>>::encode(&self.value, buf)
                        .map_err(|e| terror::Error::buffer_size_error(format!("{}", e)))?;
                }
                Ok(())
            }
        }
    };
}

macro_rules! zero_sized_transport_parameter {
    ($name:ident, $id:expr) => {
        pub struct $name {
            enabled: bool,
        }

        impl $name {
            pub fn get(&self) -> bool {
                self.enabled
            }
        }

        impl From<bool> for $name {
            fn from(b: bool) -> Self {
                Self { enabled: b }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self { enabled: false }
            }
        }

        impl TransportParameter for $name {
            const ID: usize = $id;

            type ValueType = bool;

            fn get_value(&self) -> Option<&Self::ValueType> {
                Some(&self.enabled)
            }

            fn decode(buf: &mut Octets) -> Result<Self, terror::Error> {
                buf.skip(1)
                    .map_err(|e| terror::Error::buffer_size_error(format!("{}", e)))?;
                Ok(Self { enabled: true })
            }

            fn encode(&self, buf: &mut OctetsMut) -> Result<(), terror::Error> {
                if self.enabled {
                    buf.put_varint(Self::ID as u64)
                        .map_err(|e| terror::Error::buffer_size_error(format!("{}", e)))?;
                    buf.put_u8(0x00)
                        .map_err(|e| terror::Error::buffer_size_error(format!("{}", e)))?;
                }
                Ok(())
            }
        }
    };
}

transport_parameter!(OriginalDestinationConnectionId, 0x00, ConnectionId);

impl OriginalDestinationConnectionId {
    fn validate(self) -> Result<Self, terror::Error> {
        if self.value.len() > MAX_CID_SIZE && self.value.len() > 0 {
            return Err(terror::Error::quic_transport_error(
                "malformed, badly formatted or absent original destination connection id",
                terror::QuicTransportError::TransportParameterError,
            ));
        }
        Ok(self)
    }
}

transport_parameter!(MaxIdleTimeout, 0x01, VarInt);

impl MaxIdleTimeout {
    fn validate(self) -> Result<Self, terror::Error> {
        Ok(self)
    }
}

transport_parameter!(StatelessResetTokenTP, 0x02, StatelessResetToken);

impl StatelessResetTokenTP {
    fn validate(self) -> Result<Self, terror::Error> {
        Ok(self)
    }
}

transport_parameter!(MaxUdpPayloadSize, 0x03, VarInt, 0xfff7.into());

impl MaxUdpPayloadSize {
    fn validate(self) -> Result<Self, terror::Error> {
        if !(1200..=65527).contains(&self.value.value) {
            return Err(terror::Error::quic_transport_error(
                format!("invalid maximum udp payload size of {:?}", self.value.value),
                terror::QuicTransportError::TransportParameterError,
            ));
        }
        Ok(self)
    }
}

transport_parameter!(InitialMaxData, 0x04, VarInt);

impl InitialMaxData {
    fn validate(self) -> Result<Self, terror::Error> {
        Ok(self)
    }
}

transport_parameter!(InitialMaxStreamDataBidiLocal, 0x05, VarInt);

impl InitialMaxStreamDataBidiLocal {
    fn validate(self) -> Result<Self, terror::Error> {
        Ok(self)
    }
}

transport_parameter!(InitialMaxStreamDataBidiRemote, 0x06, VarInt);

impl InitialMaxStreamDataBidiRemote {
    fn validate(self) -> Result<Self, terror::Error> {
        Ok(self)
    }
}

transport_parameter!(InitialMaxStreamDataUni, 0x07, VarInt);

impl InitialMaxStreamDataUni {
    fn validate(self) -> Result<Self, terror::Error> {
        Ok(self)
    }
}

transport_parameter!(InitialMaxStreamsBidi, 0x08, VarInt);

impl InitialMaxStreamsBidi {
    fn validate(self) -> Result<Self, terror::Error> {
        //if a stream id were to be greater than 2^60 it wouldnt be encodable as stream id
        if self.value.value > 2u64.pow(60) {
            return Err(terror::Error::quic_transport_error(
                format!(
                    "invalid maximum bidirectional streams {:?}",
                    self.value.value
                ),
                terror::QuicTransportError::TransportParameterError,
            ));
        }
        Ok(self)
    }
}

transport_parameter!(InitialMaxStreamsUni, 0x09, VarInt);

impl InitialMaxStreamsUni {
    fn validate(self) -> Result<Self, terror::Error> {
        //if a stream id were to be greater than 2^60 it wouldnt be encodable as stream id
        if self.value.value > 2u64.pow(60) {
            return Err(terror::Error::quic_transport_error(
                format!(
                    "invalid maximum unidirectional streams {:?}",
                    self.value.value
                ),
                terror::QuicTransportError::TransportParameterError,
            ));
        }
        Ok(self)
    }
}

transport_parameter!(AckDelayExponent, 0x0a, VarInt, 0x3.into());

impl AckDelayExponent {
    fn validate(self) -> Result<Self, terror::Error> {
        if self.value.value > 20 {
            return Err(terror::Error::quic_transport_error(
                "ack delay exponent cant be greater than 20",
                terror::QuicTransportError::TransportParameterError,
            ));
        }
        Ok(self)
    }
}

transport_parameter!(MaxAckDelay, 0x0b, VarInt, 0x19.into());

impl MaxAckDelay {
    fn validate(self) -> Result<Self, terror::Error> {
        if self.value.value >= 2u64.pow(14) {
            return Err(terror::Error::quic_transport_error(
                "max ack delay cant be equal or greater than 2^14",
                terror::QuicTransportError::TransportParameterError,
            ));
        }
        Ok(self)
    }
}

zero_sized_transport_parameter!(DisableActiveMigration, 0x0c);
transport_parameter!(PreferredAddress, 0x0d, PreferredAddressData);

impl PreferredAddress {
    fn validate(self) -> Result<Self, terror::Error> {
        if self.value.address_v4.is_some() || self.value.address_v6.is_some() {
            return Err(terror::Error::quic_transport_error(
                "preferred address parameter must have at least one address set",
                terror::QuicTransportError::TransportParameterError,
            ));
        }
        Ok(self)
    }
}

transport_parameter!(ActiveConnectionIdLimit, 0x0e, VarInt, 0x02.into());

impl ActiveConnectionIdLimit {
    fn validate(self) -> Result<Self, terror::Error> {
        if self.value.value < 2 {
            return Err(terror::Error::quic_transport_error(
                "active connection id limit must be at least 2",
                terror::QuicTransportError::TransportParameterError,
            ));
        }
        Ok(self)
    }
}

transport_parameter!(InitialSourceConnectionId, 0x0f, ConnectionId);

impl InitialSourceConnectionId {
    fn validate(self) -> Result<Self, terror::Error> {
        if self.value.len() > MAX_CID_SIZE && self.value.len() > 0 {
            return Err(terror::Error::quic_transport_error(
                "malformed, badly formatted or absent initial source connection id",
                terror::QuicTransportError::TransportParameterError,
            ));
        }
        Ok(self)
    }
}

transport_parameter!(RetrySourceConnectionId, 0x10, ConnectionId);

impl RetrySourceConnectionId {
    fn validate(self) -> Result<Self, terror::Error> {
        if self.value.len() > MAX_CID_SIZE && self.value.len() > 0 {
            return Err(terror::Error::quic_transport_error(
                "malformed, badly formatted or absent retry source connection id",
                terror::QuicTransportError::TransportParameterError,
            ));
        }
        Ok(self)
    }
}

//Params outside of RFC 9000
zero_sized_transport_parameter!(Grease, 0xb6);
transport_parameter!(MaxDatagramFrameSize, 0x20, VarInt, 0x00.into());

impl MaxDatagramFrameSize {
    fn validate(self) -> Result<Self, terror::Error> {
        Ok(self)
    }
}

zero_sized_transport_parameter!(GreaseQuicBit, 0x2ab2);
transport_parameter!(MinAckDelay, 0xff04de1a, VarInt);

impl MinAckDelay {
    fn validate(self) -> Result<Self, terror::Error> {
        Ok(self)
    }
}

//RFC 9000 Section 18.2
//TODO expand to RFC 9287 & draft-ietf-quic-ack-frequency
#[derive(Default)]
pub struct TransportConfig {
    pub original_destination_connection_id: OriginalDestinationConnectionId,
    pub max_idle_timeout: MaxIdleTimeout,
    pub stateless_reset_token: StatelessResetTokenTP,
    pub max_udp_payload_size: MaxUdpPayloadSize,
    pub initial_max_data: InitialMaxData,
    pub initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal,
    pub initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote,
    pub initial_max_stream_data_uni: InitialMaxStreamDataUni,
    pub initial_max_streams_bidi: InitialMaxStreamsBidi,
    pub initial_max_streams_uni: InitialMaxStreamsUni,
    pub ack_delay_exponent: AckDelayExponent,
    pub max_ack_delay: MaxAckDelay,
    pub disable_active_migration: DisableActiveMigration,
    pub preferred_address: PreferredAddress,
    pub active_connection_id_limit: ActiveConnectionIdLimit,
    pub initial_source_connection_id: InitialSourceConnectionId,
    pub retry_source_connection_id: RetrySourceConnectionId,

    //Params outside of RFC 9000
    pub grease: Grease,
    pub max_datagram_frame_size: MaxDatagramFrameSize,
    pub grease_quic_bit: GreaseQuicBit,
    pub min_ack_delay: MinAckDelay,
}

impl TransportConfig {
    pub fn decode(buf: &[u8]) -> Result<Self, terror::Error> {
        let mut tpc = Self::default();
        tpc.update(buf)?;
        Ok(tpc)
    }

    pub fn update(&mut self, buf: &[u8]) -> Result<(), terror::Error> {
        let mut b = octets::Octets::with_slice(buf);
        while let Ok(id) = b.get_varint() {
            match id {
                0x00 => {
                    self.original_destination_connection_id =
                        OriginalDestinationConnectionId::decode(&mut b)?
                }
                0x0001 => self.max_idle_timeout = MaxIdleTimeout::decode(&mut b)?,
                0x0002 => self.stateless_reset_token = StatelessResetTokenTP::decode(&mut b)?,
                0x0003 => self.max_udp_payload_size = MaxUdpPayloadSize::decode(&mut b)?,
                0x0004 => self.initial_max_data = InitialMaxData::decode(&mut b)?,
                0x0005 => {
                    self.initial_max_stream_data_bidi_local =
                        InitialMaxStreamDataBidiLocal::decode(&mut b)?
                }
                0x0006 => {
                    self.initial_max_stream_data_bidi_remote =
                        InitialMaxStreamDataBidiRemote::decode(&mut b)?
                }
                0x0007 => {
                    self.initial_max_stream_data_uni = InitialMaxStreamDataUni::decode(&mut b)?
                }
                0x0008 => self.initial_max_streams_bidi = InitialMaxStreamsBidi::decode(&mut b)?,
                0x0009 => self.initial_max_streams_uni = InitialMaxStreamsUni::decode(&mut b)?,
                0x000a => self.ack_delay_exponent = AckDelayExponent::decode(&mut b)?,
                0x000b => self.max_ack_delay = MaxAckDelay::decode(&mut b)?,
                0x000c => self.disable_active_migration = DisableActiveMigration::decode(&mut b)?,
                0x000e => {
                    self.active_connection_id_limit = ActiveConnectionIdLimit::decode(&mut b)?
                }
                0x000f => {
                    self.initial_source_connection_id = InitialSourceConnectionId::decode(&mut b)?
                }
                0x0010 => {
                    self.retry_source_connection_id = RetrySourceConnectionId::decode(&mut b)?
                }
                0x00b6 => self.grease = Grease::decode(&mut b)?,
                0x0020 => self.max_datagram_frame_size = MaxDatagramFrameSize::decode(&mut b)?,
                0x2ab2 => self.grease_quic_bit = GreaseQuicBit::decode(&mut b)?,
                0xff04de1a => self.min_ack_delay = MinAckDelay::decode(&mut b)?,
                _ => {
                    let data = b
                        .get_bytes_with_varint_length()
                        .map_err(|e| terror::Error::buffer_size_error(format!("{}", e)))?;
                    println!("unknown transport parameter with id {:x?}: {:x?}", id, data);
                }
            }
        }

        Ok(())
    }

    pub fn encode(&self, _side: rustls::Side) -> Result<Vec<u8>, terror::Error> {
        let mut vec = vec![0u8; 1024];
        let written: usize;

        {
            let mut buf = OctetsMut::with_slice(&mut vec);

            macro_rules! write_tp {
                ($name:ident) => {
                    self.$name.encode(&mut buf)?;
                };
            }

            write_tp!(original_destination_connection_id);
            write_tp!(max_idle_timeout);
            write_tp!(stateless_reset_token);
            write_tp!(max_udp_payload_size);
            write_tp!(initial_max_data);
            write_tp!(initial_max_stream_data_bidi_local);
            write_tp!(initial_max_stream_data_bidi_remote);
            write_tp!(initial_max_stream_data_uni);
            write_tp!(initial_max_streams_bidi);
            write_tp!(initial_max_streams_uni);
            write_tp!(ack_delay_exponent);
            write_tp!(max_ack_delay);
            write_tp!(disable_active_migration);
            write_tp!(preferred_address);
            write_tp!(active_connection_id_limit);
            write_tp!(initial_source_connection_id);
            write_tp!(retry_source_connection_id);

            //other transport params only after GREASE
            write_tp!(grease);
            write_tp!(max_datagram_frame_size);
            write_tp!(grease_quic_bit);
            write_tp!(min_ack_delay);

            written = buf.off();
        }

        vec.resize(written, 0x00);

        Ok(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_parameter_encoding() {
        let tpc = TransportConfig {
            grease: Grease::from(true),
            min_ack_delay: MinAckDelay::try_from(VarInt::from(1000)).unwrap(),
            ack_delay_exponent: AckDelayExponent::try_from(VarInt::from(5)).unwrap(),
            original_destination_connection_id: OriginalDestinationConnectionId::try_from(
                ConnectionId::from_vec(vec![0xab, 0xab, 0xab, 0xab]),
            )
            .unwrap(),
            ..TransportConfig::default()
        };

        let result = tpc.encode(rustls::Side::Server).unwrap();

        let expected = vec![
            0x00, 0x04, 0xab, 0xab, 0xab, 0xab, 0x0a, 0x01, 0x05, 0x40, 0xb6, 0x00, 0xc0, 0x00,
            0x00, 0x00, 0xff, 0x04, 0xde, 0x1a, 0x02, 0x43, 0xe8,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    #[should_panic]
    fn test_transport_parameter_validation() {
        AckDelayExponent::try_from(VarInt::from(21)).unwrap();
    }

    #[test]
    fn test_transport_parameter_decoding() {
        let raw = vec![
            0x01, 0x02, 0x67, 0x10, 0x03, 0x02, 0x45, 0xc0, 0x04, 0x08, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80, 0x13, 0x12, 0xd0, 0x06, 0x04, 0x80, 0x13,
            0x12, 0xd0, 0x07, 0x04, 0x80, 0x13, 0x12, 0xd0, 0x08, 0x02, 0x40, 0x64, 0x09, 0x02,
            0x40, 0x64, 0x0e, 0x01, 0x05, 0x40, 0xb6, 0x00, 0x20, 0x04, 0x80, 0x00, 0xff, 0xff,
            0x0f, 0x08, 0x03, 0x25, 0x05, 0xd0, 0x49, 0x6f, 0x4c, 0x31, 0x6a, 0xb2, 0x00, 0xc0,
            0x00, 0x00, 0x00, 0xff, 0x04, 0xde, 0x1a, 0x02, 0x43, 0xe8,
        ];

        let tpc = TransportConfig::decode(&raw).unwrap();

        assert_eq!(tpc.max_idle_timeout.get().unwrap().get(), 10000);
        assert_eq!(
            tpc.initial_source_connection_id.get().unwrap().id,
            vec![0x03, 0x25, 0x05, 0xd0, 0x49, 0x6f, 0x4c, 0x31]
        );
        assert_eq!(tpc.active_connection_id_limit.get().unwrap().get(), 5);
        assert!(tpc.grease.get());
    }
}
