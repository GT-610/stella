//! Protected peer-session Ethernet framing and bounded reassembly.

use std::{collections::BTreeMap, time::Duration};

use stella_common::{MacAddress, NodeId};
use stella_crypto::{CryptoError, ReplayWindow, SessionProtectors};
use stella_proto::{
    encode_data_packet, CommonHeader, ConfidentialityPolicy, DataHeader, DataPacketView,
    NetworkPolicy, PacketType, ProtocolVersion, AUTHENTICATION_TAG_LENGTH, DATA_ENCRYPTED_FLAG,
    DATA_FIXED_HEADER_LENGTH, MIN_ETHERNET_FRAME_LENGTH,
};
use thiserror::Error;

const MAX_INCOMPLETE_FRAMES: usize = 64;
const MAX_REASSEMBLY_BYTES: usize = 1024 * 1024;
const MAX_FRAGMENTS_PER_FRAME: usize = 128;
const DATA_HEADER_LENGTH: u16 = 104;

/// Failure while protecting or accepting Ethernet data for one peer session.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DataPlaneError {
    /// The active peer-session parameters are not internally usable.
    #[error("invalid peer data session: {reason}")]
    InvalidSession {
        /// Stable non-secret validation reason.
        reason: &'static str,
    },
    /// A complete Ethernet frame is outside the signed network limit.
    #[error("Ethernet frame length {actual} is outside 14..={maximum}")]
    InvalidFrameLength {
        /// Supplied frame length.
        actual: usize,
        /// Signed maximum frame length.
        maximum: u16,
    },
    /// The transport cannot carry even one protected fragment.
    #[error("datagram limit {actual} is below protected DATA overhead {minimum}")]
    DatagramLimitTooSmall {
        /// Configured datagram limit.
        actual: usize,
        /// Minimum usable datagram length.
        minimum: usize,
    },
    /// The send-direction packet or frame number space is exhausted.
    #[error("peer data session must rekey before {counter} counter exhaustion")]
    CounterExhausted {
        /// Exhausted counter name.
        counter: &'static str,
    },
    /// A packet belongs to another network, sender, session, or controller epoch.
    #[error("DATA packet has unexpected {field}")]
    ContextMismatch {
        /// Mismatched authenticated context field.
        field: &'static str,
    },
    /// A packet's encrypted flag disagrees with the signed policy.
    #[error("DATA packet confidentiality does not match signed network policy")]
    ConfidentialityMismatch,
    /// A protocol object was malformed or its authenticated Ethernet metadata failed validation.
    #[error(transparent)]
    Codec(#[from] stella_proto::CodecError),
    /// Packet authentication, decryption, or replay validation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// One established peer-session data direction with bounded receive state.
///
/// The object deliberately owns its non-cloneable protectors and replay window.
/// A separate instance is required for every peer session.
pub struct PeerDataSession {
    policy: NetworkPolicy,
    local_node_id: NodeId,
    peer_node_id: NodeId,
    session_id: u64,
    controller_epoch: u64,
    max_datagram_size: usize,
    protectors: SessionProtectors,
    next_sequence: Option<u64>,
    next_frame_id: Option<u64>,
    replay: ReplayWindow,
    incomplete: BTreeMap<u64, IncompleteFrame>,
    reassembly_bytes: usize,
}

impl PeerDataSession {
    /// Creates an established session bound to one network, peer, epoch, and policy.
    ///
    /// # Errors
    ///
    /// Returns [`DataPlaneError`] when identifiers are zero, policy validation
    /// fails, or the datagram limit cannot hold a protected fragment.
    pub fn new(
        policy: NetworkPolicy,
        local_node_id: NodeId,
        peer_node_id: NodeId,
        session_id: u64,
        controller_epoch: u64,
        max_datagram_size: usize,
        protectors: SessionProtectors,
    ) -> Result<Self, DataPlaneError> {
        policy.validate()?;
        if local_node_id.is_zero() {
            return Err(DataPlaneError::InvalidSession {
                reason: "local node ID is zero",
            });
        }
        if peer_node_id.is_zero() || peer_node_id == local_node_id {
            return Err(DataPlaneError::InvalidSession {
                reason: "peer node ID is zero or local",
            });
        }
        if session_id == 0 {
            return Err(DataPlaneError::InvalidSession {
                reason: "session ID is zero",
            });
        }
        if controller_epoch == 0 {
            return Err(DataPlaneError::InvalidSession {
                reason: "controller epoch is zero",
            });
        }
        let minimum = DATA_FIXED_HEADER_LENGTH + AUTHENTICATION_TAG_LENGTH + 1;
        if max_datagram_size < minimum {
            return Err(DataPlaneError::DatagramLimitTooSmall {
                actual: max_datagram_size,
                minimum,
            });
        }

        Ok(Self {
            policy,
            local_node_id,
            peer_node_id,
            session_id,
            controller_epoch,
            max_datagram_size,
            protectors,
            next_sequence: Some(1),
            next_frame_id: Some(1),
            replay: ReplayWindow::new(),
            incomplete: BTreeMap::new(),
            reassembly_bytes: 0,
        })
    }

    /// Protects one complete Ethernet frame into transport-sized datagrams.
    ///
    /// Every fragment receives a distinct sequence number. The frame counter
    /// advances only after all datagrams have been constructed successfully.
    ///
    /// # Errors
    ///
    /// Returns [`DataPlaneError`] for an invalid frame, exhausted session
    /// counters, or packet codec/protection failure.
    pub fn protect_frame(&mut self, frame: &[u8]) -> Result<Vec<Vec<u8>>, DataPlaneError> {
        self.validate_frame_length(frame.len())?;
        let frame_length =
            u16::try_from(frame.len()).map_err(|_| DataPlaneError::InvalidFrameLength {
                actual: frame.len(),
                maximum: self.policy.max_frame_size,
            })?;
        let source_mac = frame_mac(frame, 6)?;
        let destination_mac = frame_mac(frame, 0)?;
        let outer_ether_type = u16::from_be_bytes([
            *frame.get(12).ok_or(DataPlaneError::InvalidFrameLength {
                actual: frame.len(),
                maximum: self.policy.max_frame_size,
            })?,
            *frame.get(13).ok_or(DataPlaneError::InvalidFrameLength {
                actual: frame.len(),
                maximum: self.policy.max_frame_size,
            })?,
        ]);
        let maximum_fragment = self
            .max_datagram_size
            .saturating_sub(DATA_FIXED_HEADER_LENGTH + AUTHENTICATION_TAG_LENGTH)
            .min(usize::from(u16::MAX));
        let fragment_count = frame.len().div_ceil(maximum_fragment);
        if fragment_count > MAX_FRAGMENTS_PER_FRAME {
            return Err(DataPlaneError::InvalidSession {
                reason: "datagram limit requires more than 128 fragments",
            });
        }
        let first_sequence = self.next_sequence.ok_or(DataPlaneError::CounterExhausted {
            counter: "sequence",
        })?;
        let sequence_span = u64::try_from(fragment_count.saturating_sub(1)).map_err(|_| {
            DataPlaneError::CounterExhausted {
                counter: "sequence",
            }
        })?;
        let final_sequence =
            first_sequence
                .checked_add(sequence_span)
                .ok_or(DataPlaneError::CounterExhausted {
                    counter: "sequence",
                })?;
        let frame_id = self.next_frame_id.ok_or(DataPlaneError::CounterExhausted {
            counter: "frame ID",
        })?;

        let mut datagrams = Vec::new();
        datagrams.try_reserve_exact(fragment_count).map_err(|_| {
            DataPlaneError::InvalidSession {
                reason: "unable to allocate bounded datagram list",
            }
        })?;
        for (index, fragment) in frame.chunks(maximum_fragment).enumerate() {
            let index_u64 = u64::try_from(index).map_err(|_| DataPlaneError::CounterExhausted {
                counter: "sequence",
            })?;
            let offset = index
                .checked_mul(maximum_fragment)
                .and_then(|value| u16::try_from(value).ok())
                .ok_or(DataPlaneError::InvalidSession {
                    reason: "fragment offset is not representable",
                })?;
            let sequence_number =
                first_sequence
                    .checked_add(index_u64)
                    .ok_or(DataPlaneError::CounterExhausted {
                        counter: "sequence",
                    })?;
            let header = self.data_header(
                FrameHeaderFields {
                    frame_id,
                    frame_length,
                    source_mac,
                    destination_mac,
                    outer_ether_type,
                },
                FragmentHeaderFields {
                    sequence_number,
                    offset,
                    length: u16::try_from(fragment.len()).map_err(|_| {
                        DataPlaneError::InvalidSession {
                            reason: "fragment length is not representable",
                        }
                    })?,
                },
            );
            header.validate_authenticated_frame(frame)?;
            datagrams.push(self.protect_fragment(header, fragment)?);
        }

        self.next_sequence = final_sequence.checked_add(1);
        self.next_frame_id = frame_id.checked_add(1);
        Ok(datagrams)
    }

    /// Authenticates one datagram and returns a complete validated Ethernet frame.
    ///
    /// Valid authenticated fragments may be retained until their frame completes.
    /// Malformed reassembly combinations discard the affected frame and return
    /// `Ok(None)`; authentication, replay, and context failures are reported.
    ///
    /// # Errors
    ///
    /// Returns [`DataPlaneError`] for malformed packets, wrong session context,
    /// policy mismatch, failed authentication, or replay rejection.
    pub fn accept_datagram(
        &mut self,
        datagram: &[u8],
        now: Duration,
    ) -> Result<Option<Vec<u8>>, DataPlaneError> {
        self.expire(now);
        let packet = DataPacketView::decode(datagram)?;
        let header = packet.header();
        self.validate_context(header)?;
        self.replay.precheck(header.sequence_number)?;

        let mut plaintext = vec![0_u8; packet.fragment().len()];
        if header.is_encrypted() {
            self.protectors.receive().open_encrypted(
                header.sequence_number,
                packet.authenticated_header(),
                packet.fragment(),
                packet.tag(),
                &mut plaintext,
            )?;
        } else {
            self.protectors.receive().verify_authenticate_only(
                header.sequence_number,
                packet.authenticated_header(),
                packet.fragment(),
                packet.tag(),
            )?;
            plaintext.copy_from_slice(packet.fragment());
        }
        self.replay.commit(header.sequence_number)?;

        let extension_bytes = packet
            .authenticated_header()
            .get(DATA_FIXED_HEADER_LENGTH..)
            .ok_or(DataPlaneError::InvalidSession {
                reason: "validated DATA header is shorter than fixed header",
            })?;
        self.accept_fragment(header, extension_bytes, &plaintext, now)
    }

    /// Returns the highest authenticated receive sequence, if any.
    #[must_use]
    pub const fn highest_received_sequence(&self) -> Option<u64> {
        self.replay.highest()
    }

    /// Returns the number of currently incomplete frames.
    #[must_use]
    pub fn incomplete_frame_count(&self) -> usize {
        self.incomplete.len()
    }

    fn validate_frame_length(&self, length: usize) -> Result<(), DataPlaneError> {
        if !(usize::from(MIN_ETHERNET_FRAME_LENGTH)..=usize::from(self.policy.max_frame_size))
            .contains(&length)
        {
            return Err(DataPlaneError::InvalidFrameLength {
                actual: length,
                maximum: self.policy.max_frame_size,
            });
        }
        Ok(())
    }

    fn data_header(&self, frame: FrameHeaderFields, fragment: FragmentHeaderFields) -> DataHeader {
        let encrypted = self.policy.confidentiality == ConfidentialityPolicy::Encrypt;
        DataHeader {
            common: CommonHeader {
                version: ProtocolVersion::CURRENT,
                packet_type: PacketType::Data,
                flags: if encrypted { DATA_ENCRYPTED_FLAG } else { 0 },
                header_length: DATA_HEADER_LENGTH,
                payload_length: u32::from(fragment.length),
                network_id: self.policy.network_id,
            },
            sender_node_id: self.local_node_id,
            session_id: self.session_id,
            sequence_number: fragment.sequence_number,
            controller_epoch: self.controller_epoch,
            frame_id: frame.frame_id,
            frame_length: frame.frame_length,
            fragment_offset: fragment.offset,
            fragment_length: fragment.length,
            source_mac: frame.source_mac,
            destination_mac: frame.destination_mac,
            outer_ether_type: frame.outer_ether_type,
        }
    }

    fn protect_fragment(
        &self,
        header: DataHeader,
        fragment: &[u8],
    ) -> Result<Vec<u8>, DataPlaneError> {
        let encoded_length =
            usize::from(header.common.header_length) + fragment.len() + AUTHENTICATION_TAG_LENGTH;
        let mut draft = vec![0_u8; encoded_length];
        encode_data_packet(
            header,
            &[],
            fragment,
            &[0; AUTHENTICATION_TAG_LENGTH],
            &mut draft,
        )?;
        let view = DataPacketView::decode(&draft)?;
        let mut protected_fragment = vec![0_u8; fragment.len()];
        let tag = if header.is_encrypted() {
            self.protectors.send().seal_encrypted(
                header.sequence_number,
                view.authenticated_header(),
                fragment,
                &mut protected_fragment,
            )?
        } else {
            protected_fragment.copy_from_slice(fragment);
            self.protectors.send().authenticate_only(
                header.sequence_number,
                view.authenticated_header(),
                fragment,
            )?
        };
        let mut encoded = vec![0_u8; encoded_length];
        encode_data_packet(header, &[], &protected_fragment, &tag, &mut encoded)?;
        Ok(encoded)
    }

    fn validate_context(&self, header: DataHeader) -> Result<(), DataPlaneError> {
        if header.common.network_id != self.policy.network_id {
            return Err(DataPlaneError::ContextMismatch {
                field: "network ID",
            });
        }
        if header.sender_node_id != self.peer_node_id {
            return Err(DataPlaneError::ContextMismatch {
                field: "sender node ID",
            });
        }
        if header.session_id != self.session_id {
            return Err(DataPlaneError::ContextMismatch {
                field: "session ID",
            });
        }
        if header.controller_epoch != self.controller_epoch {
            return Err(DataPlaneError::ContextMismatch {
                field: "controller epoch",
            });
        }
        if header.frame_length > self.policy.max_frame_size {
            return Err(DataPlaneError::InvalidFrameLength {
                actual: usize::from(header.frame_length),
                maximum: self.policy.max_frame_size,
            });
        }
        let expected_encryption = self.policy.confidentiality == ConfidentialityPolicy::Encrypt;
        if header.is_encrypted() != expected_encryption {
            return Err(DataPlaneError::ConfidentialityMismatch);
        }
        Ok(())
    }

    fn accept_fragment(
        &mut self,
        header: DataHeader,
        extension_bytes: &[u8],
        fragment: &[u8],
        now: Duration,
    ) -> Result<Option<Vec<u8>>, DataPlaneError> {
        if header.fragment_offset == 0 && header.fragment_length == header.frame_length {
            header.validate_authenticated_frame(fragment)?;
            return Ok(Some(fragment.to_vec()));
        }

        let metadata = FrameMetadata::new(header, extension_bytes);
        if let Some(existing) = self.incomplete.get(&header.frame_id) {
            if existing.metadata != metadata {
                self.remove_incomplete(header.frame_id);
                return Ok(None);
            }
        } else {
            self.make_reassembly_room(usize::from(header.frame_length));
            if self.incomplete.len() >= MAX_INCOMPLETE_FRAMES
                || self.reassembly_bytes + usize::from(header.frame_length) > MAX_REASSEMBLY_BYTES
            {
                return Ok(None);
            }
            let candidate = IncompleteFrame::new(metadata, now)?;
            self.reassembly_bytes += candidate.bytes.len();
            self.incomplete.insert(header.frame_id, candidate);
        }

        let result = self
            .incomplete
            .get_mut(&header.frame_id)
            .map_or(FragmentResult::Conflict, |frame| {
                frame.insert(header.fragment_offset, fragment)
            });
        match result {
            FragmentResult::Accepted | FragmentResult::Duplicate => Ok(None),
            FragmentResult::Conflict => {
                self.remove_incomplete(header.frame_id);
                Ok(None)
            }
            FragmentResult::Complete => {
                let Some(frame) = self.incomplete.remove(&header.frame_id) else {
                    return Ok(None);
                };
                self.reassembly_bytes = self.reassembly_bytes.saturating_sub(frame.bytes.len());
                frame
                    .metadata
                    .header
                    .validate_authenticated_frame(&frame.bytes)?;
                Ok(Some(frame.bytes))
            }
        }
    }

    fn expire(&mut self, now: Duration) {
        let timeout = Duration::from_millis(u64::from(self.policy.reassembly_timeout_ms));
        let expired: Vec<u64> = self
            .incomplete
            .iter()
            .filter_map(|(frame_id, frame)| {
                (now.saturating_sub(frame.first_seen) >= timeout).then_some(*frame_id)
            })
            .collect();
        for frame_id in expired {
            self.remove_incomplete(frame_id);
        }
    }

    fn make_reassembly_room(&mut self, needed: usize) {
        while self.incomplete.len() >= MAX_INCOMPLETE_FRAMES
            || self.reassembly_bytes.saturating_add(needed) > MAX_REASSEMBLY_BYTES
        {
            let oldest = self
                .incomplete
                .iter()
                .min_by_key(|(frame_id, frame)| (frame.first_seen, **frame_id))
                .map(|(frame_id, _)| *frame_id);
            let Some(frame_id) = oldest else {
                break;
            };
            self.remove_incomplete(frame_id);
        }
    }

    fn remove_incomplete(&mut self, frame_id: u64) {
        if let Some(frame) = self.incomplete.remove(&frame_id) {
            self.reassembly_bytes = self.reassembly_bytes.saturating_sub(frame.bytes.len());
        }
    }
}

impl std::fmt::Debug for PeerDataSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerDataSession")
            .field("network_id", &self.policy.network_id)
            .field("local_node_id", &self.local_node_id)
            .field("peer_node_id", &self.peer_node_id)
            .field("session_id", &self.session_id)
            .field("controller_epoch", &self.controller_epoch)
            .field("highest_received_sequence", &self.replay.highest())
            .field("incomplete_frames", &self.incomplete.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FrameMetadata {
    header: DataHeader,
    extension_bytes: Vec<u8>,
}

impl FrameMetadata {
    fn new(mut header: DataHeader, extension_bytes: &[u8]) -> Self {
        header.sequence_number = 1;
        header.fragment_offset = 0;
        header.fragment_length = 1;
        header.common.payload_length = 1;
        Self {
            header,
            extension_bytes: extension_bytes.to_vec(),
        }
    }
}

#[derive(Debug)]
struct IncompleteFrame {
    metadata: FrameMetadata,
    first_seen: Duration,
    bytes: Vec<u8>,
    ranges: BTreeMap<u16, u16>,
    received_bytes: usize,
}

impl IncompleteFrame {
    fn new(metadata: FrameMetadata, first_seen: Duration) -> Result<Self, DataPlaneError> {
        let frame_length = usize::from(metadata.header.frame_length);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(frame_length)
            .map_err(|_| DataPlaneError::InvalidSession {
                reason: "unable to allocate bounded reassembly frame",
            })?;
        bytes.resize(frame_length, 0);
        Ok(Self {
            metadata,
            first_seen,
            bytes,
            ranges: BTreeMap::new(),
            received_bytes: 0,
        })
    }

    fn insert(&mut self, offset: u16, fragment: &[u8]) -> FragmentResult {
        let Ok(length) = u16::try_from(fragment.len()) else {
            return FragmentResult::Conflict;
        };
        let Some(end) = offset.checked_add(length) else {
            return FragmentResult::Conflict;
        };
        if usize::from(end) > self.bytes.len() {
            return FragmentResult::Conflict;
        }
        if let Some(existing_length) = self.ranges.get(&offset) {
            if *existing_length == length
                && self.bytes.get(usize::from(offset)..usize::from(end)) == Some(fragment)
            {
                return FragmentResult::Duplicate;
            }
            return FragmentResult::Conflict;
        }
        if self.ranges.len() >= MAX_FRAGMENTS_PER_FRAME
            || self
                .ranges
                .iter()
                .any(|(existing_offset, existing_length)| {
                    let existing_end = existing_offset.saturating_add(*existing_length);
                    offset < existing_end && *existing_offset < end
                })
        {
            return FragmentResult::Conflict;
        }
        let Some(output) = self.bytes.get_mut(usize::from(offset)..usize::from(end)) else {
            return FragmentResult::Conflict;
        };
        output.copy_from_slice(fragment);
        self.ranges.insert(offset, length);
        self.received_bytes += fragment.len();
        if self.received_bytes == self.bytes.len() {
            FragmentResult::Complete
        } else {
            FragmentResult::Accepted
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FragmentResult {
    Accepted,
    Duplicate,
    Complete,
    Conflict,
}

#[derive(Clone, Copy, Debug)]
struct FrameHeaderFields {
    frame_id: u64,
    frame_length: u16,
    source_mac: MacAddress,
    destination_mac: MacAddress,
    outer_ether_type: u16,
}

#[derive(Clone, Copy, Debug)]
struct FragmentHeaderFields {
    sequence_number: u64,
    offset: u16,
    length: u16,
}

fn frame_mac(frame: &[u8], offset: usize) -> Result<MacAddress, DataPlaneError> {
    let end = offset + MacAddress::LENGTH;
    let bytes = frame
        .get(offset..end)
        .and_then(|value| <[u8; MacAddress::LENGTH]>::try_from(value).ok())
        .ok_or(DataPlaneError::InvalidFrameLength {
            actual: frame.len(),
            maximum: u16::try_from(frame.len()).unwrap_or(u16::MAX),
        })?;
    Ok(MacAddress::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::{DataPlaneError, PeerDataSession};
    use std::time::Duration;
    use stella_common::{NetworkId, NodeId};
    use stella_crypto::{
        derive_session_secrets, session_transcript_hash, EphemeralPublicKey, EphemeralSecret,
        SessionRole,
    };
    use stella_proto::{ConfidentialityPolicy, DataPacketView, NetworkPolicy};

    const ALICE_SECRET: [u8; 32] = [7; 32];
    const BOB_SECRET: [u8; 32] = [9; 32];

    fn policy(confidentiality: ConfidentialityPolicy) -> NetworkPolicy {
        NetworkPolicy {
            confidentiality,
            max_frame_size: 1_514,
            max_flood_peers: 8,
            flood_rate: 1_000,
            flood_burst: 2_000,
            mac_age_seconds: 300,
            heartbeat_seconds: 10,
            peer_lease_seconds: 30,
            session_lifetime_seconds: 900,
            reassembly_timeout_ms: 3_000,
            network_id: NetworkId::from_bytes([1; 16]),
            policy_revision: 1,
        }
    }

    fn sessions(
        confidentiality: ConfidentialityPolicy,
        datagram_size: usize,
    ) -> (PeerDataSession, PeerDataSession) {
        let alice_secret = EphemeralSecret::from_bytes(ALICE_SECRET);
        let bob_secret = EphemeralSecret::from_bytes(BOB_SECRET);
        let alice_public = alice_secret.public_key();
        let bob_public = bob_secret.public_key();
        let transcript = session_transcript_hash(b"init", b"response");
        let alice_shared = alice_secret
            .agree(EphemeralPublicKey::from_bytes(bob_public.to_bytes()))
            .expect("contributory agreement");
        let bob_shared = bob_secret
            .agree(EphemeralPublicKey::from_bytes(alice_public.to_bytes()))
            .expect("contributory agreement");
        let alice = derive_session_secrets(alice_shared, &transcript, SessionRole::Initiator)
            .expect("derive initiator")
            .into_protectors();
        let bob = derive_session_secrets(bob_shared, &transcript, SessionRole::Responder)
            .expect("derive responder")
            .into_protectors();
        let alice_id = NodeId::from_bytes([2; 16]);
        let bob_id = NodeId::from_bytes([3; 16]);
        (
            PeerDataSession::new(
                policy(confidentiality),
                alice_id,
                bob_id,
                41,
                7,
                datagram_size,
                alice,
            )
            .expect("alice session"),
            PeerDataSession::new(
                policy(confidentiality),
                bob_id,
                alice_id,
                41,
                7,
                datagram_size,
                bob,
            )
            .expect("bob session"),
        )
    }

    fn frame(payload_length: usize) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + payload_length];
        frame[..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        for (index, byte) in frame[14..].iter_mut().enumerate() {
            *byte = u8::try_from(index % 251).expect("bounded pattern");
        }
        frame
    }

    #[test]
    fn encrypted_fragments_reassemble_out_of_order() {
        let (mut alice, mut bob) = sessions(ConfidentialityPolicy::Encrypt, 220);
        let frame = frame(900);
        let mut datagrams = alice.protect_frame(&frame).expect("protect frame");
        assert!(datagrams.len() > 1);
        datagrams.reverse();
        let mut completed = None;
        for datagram in datagrams {
            let accepted = bob
                .accept_datagram(&datagram, Duration::from_millis(1))
                .expect("authenticate fragment");
            if accepted.is_some() {
                completed = accepted;
            }
        }
        assert_eq!(completed, Some(frame));
        assert_eq!(bob.incomplete_frame_count(), 0);
    }

    #[test]
    fn authenticate_only_round_trips_and_replay_is_rejected() {
        let (mut alice, mut bob) = sessions(ConfidentialityPolicy::AuthenticateOnly, 1_500);
        let frame = frame(64);
        let datagram = alice
            .protect_frame(&frame)
            .expect("protect frame")
            .remove(0);
        assert_eq!(
            bob.accept_datagram(&datagram, Duration::ZERO)
                .expect("first packet"),
            Some(frame)
        );
        assert!(matches!(
            bob.accept_datagram(&datagram, Duration::ZERO),
            Err(DataPlaneError::Crypto(_))
        ));
    }

    #[test]
    fn failed_tag_does_not_advance_replay_window() {
        let (mut alice, mut bob) = sessions(ConfidentialityPolicy::Encrypt, 1_500);
        let mut datagram = alice
            .protect_frame(&frame(64))
            .expect("protect frame")
            .remove(0);
        let tag_index = datagram.len() - 1;
        datagram[tag_index] ^= 1;
        assert!(bob.accept_datagram(&datagram, Duration::ZERO).is_err());
        assert_eq!(bob.highest_received_sequence(), None);
        datagram[tag_index] ^= 1;
        assert!(bob
            .accept_datagram(&datagram, Duration::ZERO)
            .expect("valid retry")
            .is_some());
        assert_eq!(bob.highest_received_sequence(), Some(1));
    }

    #[test]
    fn conflicting_overlap_discards_incomplete_frame() {
        let (mut alice, mut bob) = sessions(ConfidentialityPolicy::Encrypt, 220);
        let frame = frame(400);
        let mut datagrams = alice.protect_frame(&frame).expect("protect frame");
        let first = datagrams.remove(0);
        assert_eq!(
            bob.accept_datagram(&first, Duration::ZERO)
                .expect("first fragment"),
            None
        );
        assert_eq!(bob.incomplete_frame_count(), 1);

        let conflicting_header = alice.data_header(
            super::FrameHeaderFields {
                frame_id: 1,
                frame_length: u16::try_from(frame.len()).expect("bounded frame"),
                source_mac: stella_common::MacAddress::from_bytes([0x02, 0, 0, 0, 0, 1]),
                destination_mac: stella_common::MacAddress::BROADCAST,
                outer_ether_type: 0x0800,
            },
            super::FragmentHeaderFields {
                sequence_number: 100,
                offset: 50,
                length: 100,
            },
        );
        let conflicting = alice
            .protect_fragment(conflicting_header, &frame[50..150])
            .expect("protect overlapping authenticated fragment");
        assert_eq!(
            bob.accept_datagram(&conflicting, Duration::ZERO)
                .expect("authenticated conflict is dropped"),
            None
        );
        assert_eq!(bob.incomplete_frame_count(), 0);
    }

    #[test]
    fn timeout_discards_incomplete_frame() {
        let (mut alice, mut bob) = sessions(ConfidentialityPolicy::Encrypt, 220);
        let datagrams = alice.protect_frame(&frame(400)).expect("protect frame");
        bob.accept_datagram(&datagrams[0], Duration::ZERO)
            .expect("first fragment");
        assert_eq!(bob.incomplete_frame_count(), 1);
        bob.accept_datagram(&datagrams[1], Duration::from_secs(4))
            .expect("new fragment after timeout");
        assert_eq!(bob.incomplete_frame_count(), 1);
    }

    #[test]
    fn confidentiality_and_context_are_fail_closed() {
        let (mut alice, mut bob) = sessions(ConfidentialityPolicy::Encrypt, 1_500);
        let datagram = alice
            .protect_frame(&frame(64))
            .expect("protect frame")
            .remove(0);
        let decoded = DataPacketView::decode(&datagram).expect("valid packet");
        assert!(decoded.header().is_encrypted());

        bob.policy.confidentiality = ConfidentialityPolicy::AuthenticateOnly;
        assert!(matches!(
            bob.accept_datagram(&datagram, Duration::ZERO),
            Err(DataPlaneError::ConfidentialityMismatch)
        ));
        assert_eq!(bob.highest_received_sequence(), None);
    }
}
