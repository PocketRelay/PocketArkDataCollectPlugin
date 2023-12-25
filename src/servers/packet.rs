//! Packet implementation for creating [`Packet`]s along with types
//! used by the router for creating and decoding contents / responses
//!
//! Also contains the decoding and encoding logic for tokio codec
//! [`PacketCodec`]

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use std::{fmt::Debug, hash::Hash};
use tdf::{TdfDeserializer, TdfStringifier};
use tokio_util::codec::{Decoder, Encoder};

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct FrameFlags: u8 {
        const FLAG_DEFAULT = 0;
        const FLAG_RESPONSE = 32;
        const FLAG_NOTIFY = 64;
        const FLAG_KEEP_ALIVE = 128;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FireFrame2 {
    pub component: u16,
    pub command: u16,
    pub seq: u32,
    pub flags: FrameFlags,
    pub notify: u8,
    pub unused: u8,
}

/// Structure for Blaze packets contains the contents of the packet
/// and the header for identification.
///
/// Packets can be cloned with little memory usage increase because
/// the content is stored as Bytes.
#[derive(Debug, Clone)]
pub struct Packet {
    pub frame: FireFrame2,
    pub pre_msg: Bytes,
    pub contents: Bytes,
}

impl Packet {
    /// Attempts to read a packet from the provided
    /// bytes source
    ///
    /// `src` The bytes to read from
    pub fn read(src: &mut BytesMut) -> Option<Self> {
        if src.len() < 16 {
            return None;
        }

        let length = src.get_u32();
        let pre_length = src.get_u16();
        let component = src.get_u16();
        let command = src.get_u16();
        let mut seq = [0u8; 4];

        src.take(3).copy_to_slice(&mut seq[1..]);
        let seq = u32::from_be_bytes(seq);
        let mty = src.get_u8();
        let flags = FrameFlags::from_bits_retain(mty);
        let notify = src.get_u8();
        let unused = src.get_u8();

        if src.len() < pre_length as usize + length as usize {
            return None;
        }
        let pre_msg = src.split_to(pre_length as usize);
        let body = src.split_to(length as usize);

        Some(Packet {
            frame: FireFrame2 {
                component,
                command,
                seq,
                flags,
                notify,
                unused,
            },
            pre_msg: pre_msg.freeze(),
            contents: body.freeze(),
        })
    }

    /// Writes the contents and header of the packet
    /// onto the dst source of bytes
    ///
    /// `dst` The destination buffer
    pub fn write(&self, dst: &mut BytesMut) {
        dst.put_u32(self.contents.len() as u32);
        dst.put_u16(self.pre_msg.len() as u16);
        dst.put_u16(self.frame.component);
        dst.put_u16(self.frame.command);

        let seq = self.frame.seq.to_be_bytes();
        dst.put_slice(&seq[1..]);

        let ty = self.frame.flags.bits();
        dst.put_u8(ty);
        dst.put_u8(self.frame.notify);
        dst.put_u8(self.frame.unused);
        dst.extend_from_slice(&self.pre_msg);
        dst.extend_from_slice(&self.contents);
    }
}

/// Tokio codec for encoding and decoding packets
pub struct PacketCodec;

/// Decoder implementation
impl Decoder for PacketCodec {
    type Error = io::Error;
    type Item = Packet;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut read_src = src.clone();
        let result = Packet::read(&mut read_src);

        if result.is_some() {
            *src = read_src;
        }

        Ok(result)
    }
}

/// Encoder implementation for owned packets
impl Encoder<Packet> for PacketCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Packet, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.write(dst);
        Ok(())
    }
}

/// Wrapper over a packet structure to provde debug logging
/// with names resolved for the component
pub struct PacketDebug<'a> {
    /// Reference to the packet itself
    pub packet: &'a Packet,
}

impl<'a> Debug for PacketDebug<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Append basic header information
        let header = &self.packet.frame;

        writeln!(f, "Component: {:#06x}", header.component)?;
        writeln!(f, "Command: {:#06x}", header.command)?;

        writeln!(f, "Flags: {:?}", header.flags)?;
        writeln!(f, "Seq: {}", &header.seq)?;
        writeln!(f, "Notif: {}", &header.notify)?;
        writeln!(f, "Unused: {}", &header.unused)?;

        if !self.packet.pre_msg.is_empty() {
            let r = TdfDeserializer::new(&self.packet.pre_msg);
            let mut out = String::new();

            out.push_str("{\n");
            let mut s = TdfStringifier::new(r, &mut out);

            let _ = s.stringify();

            if out.len() == 2 {
                // Remove new line if nothing else was appended
                out.pop();
            }

            out.push('}');

            writeln!(f, "Pre Message: {}", out)?;
        }

        let r = TdfDeserializer::new(&self.packet.contents);
        let mut out = String::new();

        let mut s = TdfStringifier::new(r, &mut out);

        let _ = s.stringify();

        write!(f, "Content: {}", out)
    }
}
