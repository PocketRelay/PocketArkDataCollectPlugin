//! Packet implementation for creating [`Packet`]s along with types
//! used by the router for creating and decoding contents / responses
//!
//! Also contains the decoding and encoding logic for tokio codec
//! [`PacketCodec`]

use pocket_ark_blaze_networking::Packet;
use std::fmt::Debug;
use tdf::{TdfDeserializer, TdfStringifier};

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
