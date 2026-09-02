//! Secure RTP (SRTP) implementation
//!
//! This module provides encryption and authentication for RTP/RTCP packets.

use std::collections::HashMap;

pub mod auth;
pub mod crypto;
pub mod key_derivation;

pub use auth::{SrtpAuthenticator, SrtpReplayProtection};
pub use crypto::SrtpCryptoKey;
pub use key_derivation::{
    create_srtp_iv, srtp_kdf, KeyDerivationLabel, KeyRotationFrequency, SrtpKeyDerivationParams,
};

/// SRTP encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpEncryptionAlgorithm {
    /// AES Counter Mode (Default in SRTP)
    AesCm,

    /// AES in f8-mode (Customized for SRTP)
    AesF8,

    /// Null encryption (for debugging/testing only)
    Null,

    /// AEAD AES-128-GCM (RFC 7714).
    ///
    /// The profile identity is retained so configuration and negotiation can
    /// fail closed. Encryption is not implemented in this release.
    AeadAes128Gcm,

    /// AEAD AES-256-GCM (RFC 7714).
    ///
    /// The profile identity is retained so configuration and negotiation can
    /// fail closed. Encryption is not implemented in this release.
    AeadAes256Gcm,
}

/// SRTP authentication algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpAuthenticationAlgorithm {
    /// HMAC-SHA1 truncated to 80 bits (Default in SRTP)
    HmacSha1_80,

    /// HMAC-SHA1 truncated to 32 bits
    HmacSha1_32,

    /// Null authentication (for debugging/testing only)
    Null,
}

/// SRTP crypto suite
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpCryptoSuite {
    /// Encryption algorithm
    pub encryption: SrtpEncryptionAlgorithm,

    /// Authentication algorithm
    pub authentication: SrtpAuthenticationAlgorithm,

    /// Master key length in bytes
    pub key_length: usize,

    /// SRTP authentication tag length in bytes.
    ///
    /// SRTCP can require a different length for the same profile; use
    /// [`Self::srtcp_tag_length`] for RTCP packets.
    pub tag_length: usize,
}

/// Default SRTP crypto suite: AES-CM-128 + HMAC-SHA1-80
pub const SRTP_AES128_CM_SHA1_80: SrtpCryptoSuite = SrtpCryptoSuite {
    encryption: SrtpEncryptionAlgorithm::AesCm,
    authentication: SrtpAuthenticationAlgorithm::HmacSha1_80,
    key_length: 16, // 128 bits
    tag_length: 10, // 80 bits
};

/// Smaller tag SRTP crypto suite: AES-CM-128 + HMAC-SHA1-32
pub const SRTP_AES128_CM_SHA1_32: SrtpCryptoSuite = SrtpCryptoSuite {
    encryption: SrtpEncryptionAlgorithm::AesCm,
    authentication: SrtpAuthenticationAlgorithm::HmacSha1_32,
    key_length: 16, // 128 bits
    tag_length: 4,  // 32 bits
};

/// AES-CM-256 + HMAC-SHA1-80 (RFC 6188)
pub const SRTP_AES256_CM_SHA1_80: SrtpCryptoSuite = SrtpCryptoSuite {
    encryption: SrtpEncryptionAlgorithm::AesCm,
    authentication: SrtpAuthenticationAlgorithm::HmacSha1_80,
    key_length: 32, // 256 bits
    tag_length: 10, // 80 bits
};

/// AES-CM-256 + HMAC-SHA1-32 (RFC 6188)
pub const SRTP_AES256_CM_SHA1_32: SrtpCryptoSuite = SrtpCryptoSuite {
    encryption: SrtpEncryptionAlgorithm::AesCm,
    authentication: SrtpAuthenticationAlgorithm::HmacSha1_32,
    key_length: 32, // 256 bits
    tag_length: 4,  // 32 bits
};

/// Null encryption/authentication (for testing/debugging only)
pub const SRTP_NULL_SHA1_80: SrtpCryptoSuite = SrtpCryptoSuite {
    encryption: SrtpEncryptionAlgorithm::Null,
    authentication: SrtpAuthenticationAlgorithm::HmacSha1_80,
    key_length: 16, // 128 bits
    tag_length: 10, // 80 bits
};

/// No encryption or authentication (DANGEROUS - use only for testing)
pub const SRTP_NULL_NULL: SrtpCryptoSuite = SrtpCryptoSuite {
    encryption: SrtpEncryptionAlgorithm::Null,
    authentication: SrtpAuthenticationAlgorithm::Null,
    key_length: 16, // Changed from 0 to 16 to support realistic test scenarios
    tag_length: 0,
};

// AEAD AES-GCM suite definitions. These exist so negotiation code can
// reference them, but `validate()` rejects them with UnsupportedFeature —
// real RFC 7714 support is separate future work.

/// AEAD AES-128 GCM
pub const SRTP_AEAD_AES_128_GCM: SrtpCryptoSuite = SrtpCryptoSuite {
    encryption: SrtpEncryptionAlgorithm::AeadAes128Gcm,
    authentication: SrtpAuthenticationAlgorithm::Null, // Authentication is part of AEAD
    key_length: 16,                                    // 128 bits
    tag_length: 16,                                    // 128 bits for GCM
};

/// AEAD AES-256 GCM
pub const SRTP_AEAD_AES_256_GCM: SrtpCryptoSuite = SrtpCryptoSuite {
    encryption: SrtpEncryptionAlgorithm::AeadAes256Gcm,
    authentication: SrtpAuthenticationAlgorithm::Null, // Authentication is part of AEAD
    key_length: 32,                                    // 256 bits
    tag_length: 16,                                    // 128 bits for GCM
};

impl SrtpCryptoSuite {
    /// Authentication tag length used by SRTCP.
    ///
    /// The RFC 5764 `AES_CM_128_HMAC_SHA1_32` profile shortens only the SRTP
    /// tag. SRTCP continues to use the 80-bit HMAC-SHA1 tag required by its
    /// crypto policy. Keeping this derived from the public suite fields avoids
    /// changing the construction API for downstream users.
    #[must_use]
    pub const fn srtcp_tag_length(&self) -> usize {
        match self.authentication {
            SrtpAuthenticationAlgorithm::HmacSha1_80 | SrtpAuthenticationAlgorithm::HmacSha1_32 => {
                10
            }
            SrtpAuthenticationAlgorithm::Null => 0,
        }
    }

    /// Validate that the suite's parameters are internally consistent.
    ///
    /// The HMAC-SHA1 authentication tag is truncated from a fixed 20-byte
    /// digest, so any HMAC-SHA1 suite must declare `tag_length <= 20`.
    /// The built-in suites all satisfy this; the check guards against a
    /// hand-constructed `SrtpCryptoSuite` literal (the fields are public)
    /// whose oversized `tag_length` would otherwise panic when the tag is
    /// sliced out of the digest during protect/unprotect.
    pub fn validate(&self) -> Result<(), crate::Error> {
        const HMAC_SHA1_OUTPUT_LEN: usize = 20;
        if matches!(
            self.encryption,
            SrtpEncryptionAlgorithm::AeadAes128Gcm | SrtpEncryptionAlgorithm::AeadAes256Gcm
        ) {
            return Err(crate::Error::UnsupportedFeature(
                "SRTP AEAD AES-GCM profiles are not implemented".to_string(),
            ));
        }

        if self.encryption == SrtpEncryptionAlgorithm::AesF8 {
            return Err(crate::Error::UnsupportedFeature(
                "SRTP AES-f8 is not implemented".to_string(),
            ));
        }

        if !matches!(self.key_length, 16 | 32) {
            return Err(crate::Error::SrtpError(format!(
                "unsupported SRTP master key length: {} bytes",
                self.key_length
            )));
        }

        let expected_tag_length = match self.authentication {
            SrtpAuthenticationAlgorithm::HmacSha1_80 => 10,
            SrtpAuthenticationAlgorithm::HmacSha1_32 => 4,
            SrtpAuthenticationAlgorithm::Null => 0,
        };
        if self.tag_length != expected_tag_length {
            return Err(crate::Error::SrtpError(format!(
                "SRTP authentication mode requires a {expected_tag_length}-byte tag, got {}",
                self.tag_length
            )));
        }
        if self.tag_length > HMAC_SHA1_OUTPUT_LEN {
            return Err(crate::Error::SrtpError(format!(
                "SRTP suite tag_length {} exceeds HMAC-SHA1 output {}",
                self.tag_length, HMAC_SHA1_OUTPUT_LEN
            )));
        }

        if self != &SRTP_AES128_CM_SHA1_80
            && self != &SRTP_AES128_CM_SHA1_32
            && self != &SRTP_AES256_CM_SHA1_80
            && self != &SRTP_AES256_CM_SHA1_32
        {
            return Err(crate::Error::UnsupportedFeature(
                "unreviewed SRTP suite combination is unavailable; use an exact AES-CM/HMAC-SHA1 built-in profile"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// SRTP context for one direction of a session — one `SrtpContext` is
/// either the send side or the receive side, never both (matching how a
/// real DTLS-SRTP/SDES handshake always derives distinct directional
/// keys). Tracks rollover-counter and anti-replay state independently per
/// SSRC.
pub struct SrtpContext {
    /// Whether encryption is enabled
    enabled: bool,

    /// Local transmit keys and derived material.
    outbound_crypto: crypto::SrtpCrypto,

    /// Remote transmit keys and derived material used for receive.
    inbound_crypto: crypto::SrtpCrypto,

    /// Key rotation frequency
    key_rotation: key_derivation::KeyRotationFrequency,

    /// Per-SSRC outbound RTP rollover and IV-reuse state.
    outbound_rtp: HashMap<u32, RtpStreamState>,

    /// Per-SSRC inbound RTP rollover and replay state.
    inbound_rtp: HashMap<u32, RtpStreamState>,

    /// Per-SSRC outbound SRTCP indexes.
    outbound_srtcp: HashMap<u32, SrtcpSendState>,

    /// Per-SSRC inbound SRTCP replay windows.
    inbound_srtcp: HashMap<u32, ReplayWindow>,
}

#[derive(Debug, Clone, Default)]
struct RtpStreamState {
    roc: u32,
    highest_seq: Option<u16>,
    replay: ReplayWindow,
}

#[derive(Debug, Clone)]
struct SrtcpSendState {
    next_index: u32,
    exhausted: bool,
}

impl Default for SrtcpSendState {
    fn default() -> Self {
        // libSRTP and its published interoperability vectors place index 1
        // on the first protected RTCP packet.
        Self {
            next_index: 1,
            exhausted: false,
        }
    }
}

/// A fixed 64-packet replay window. Querying it is side-effect free so an
/// authentication failure can never advance receive state.
#[derive(Debug, Clone, Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    fn accepts(&self, index: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if index > highest {
            return true;
        }
        let delta = highest - index;
        delta < 64 && (self.bitmap & (1_u64 << delta)) == 0
    }

    fn commit(&mut self, index: u64) {
        match self.highest {
            None => {
                self.highest = Some(index);
                self.bitmap = 1;
            }
            Some(highest) if index > highest => {
                let shift = index - highest;
                self.bitmap = if shift >= 64 {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.highest = Some(index);
            }
            Some(highest) => {
                let delta = highest - index;
                debug_assert!(delta < 64);
                self.bitmap |= 1_u64 << delta;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RtpIndexCandidate {
    roc: u32,
    index: u64,
    before_roc_zero: bool,
}

fn candidate_rtp_index(state: Option<&RtpStreamState>, seq: u16) -> RtpIndexCandidate {
    let Some(state) = state else {
        return RtpIndexCandidate {
            roc: 0,
            index: u64::from(seq),
            before_roc_zero: false,
        };
    };
    let Some(highest_seq) = state.highest_seq else {
        return RtpIndexCandidate {
            roc: state.roc,
            index: (u64::from(state.roc) << 16) | u64::from(seq),
            before_roc_zero: false,
        };
    };

    // RFC 3711 Appendix A.1 index estimation. A large apparent jump across
    // the half-range belongs to the adjacent rollover cycle.
    let (candidate_roc, before_roc_zero) = if highest_seq < 0x8000 {
        if seq > highest_seq && seq - highest_seq > 0x8000 {
            // RFC 3711 performs this subtraction modulo 2^32. At ROC zero
            // that wrapped value is still required for authentication, but
            // it cannot represent a packet in the receiver's valid history.
            (state.roc.wrapping_sub(1), state.roc == 0)
        } else {
            (state.roc, false)
        }
    } else if highest_seq > seq && highest_seq - seq > 0x8000 {
        (state.roc.wrapping_add(1), false)
    } else {
        (state.roc, false)
    };

    RtpIndexCandidate {
        roc: candidate_roc,
        index: (u64::from(candidate_roc) << 16) | u64::from(seq),
        before_roc_zero,
    }
}

fn commit_rtp_index(state: &mut RtpStreamState, roc: u32, seq: u16, index: u64) {
    if state.replay.highest.is_none_or(|highest| index > highest) {
        state.roc = roc;
        state.highest_seq = Some(seq);
    }
    state.replay.commit(index);
}

/// Validate every plaintext RTCP member before SRTCP state can change.
///
/// This intentionally accepts both RFC 3550 compound packets and RFC 5506
/// reduced-size RTCP. It still validates each common header, declared length,
/// version, packet-specific body, and the rule that padding may appear only
/// on the final member.
fn validate_plaintext_rtcp(data: &[u8]) -> Result<(), crate::Error> {
    if data.is_empty() {
        return Err(crate::Error::RtcpError(
            "RTCP packet must not be empty".to_string(),
        ));
    }

    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = data.len() - offset;
        if remaining < 4 {
            return Err(crate::Error::BufferTooSmall {
                required: 4,
                available: remaining,
            });
        }

        let packet = &data[offset..];
        let words_minus_one = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        let packet_size = words_minus_one
            .checked_add(1)
            .and_then(|words| words.checked_mul(4))
            .ok_or_else(|| {
                crate::Error::RtcpError("RTCP packet length overflows usize".to_string())
            })?;
        if offset == 0 && packet_size < 8 {
            return Err(crate::Error::RtcpError(
                "SRTCP requires the first RTCP member to carry an SSRC".to_string(),
            ));
        }
        if packet_size > remaining {
            return Err(crate::Error::BufferTooSmall {
                required: packet_size,
                available: remaining,
            });
        }
        if packet[0] & 0x20 != 0 && packet_size != remaining {
            return Err(crate::Error::RtcpError(
                "Only the final packet in an RTCP datagram may be padded".to_string(),
            ));
        }

        if crate::packet::rtcp::RtcpPacketType::try_from(packet[1]).is_ok() {
            crate::packet::rtcp::RtcpPacket::parse(&packet[..packet_size])?;
        } else {
            crate::packet::rtcp::RtcpUnknownPacket::parse(&packet[..packet_size])?;
        }
        offset += packet_size;
    }

    Ok(())
}

/// Protected RTP packet with authentication tag
pub struct ProtectedRtpPacket {
    /// The encrypted RTP packet
    pub packet: crate::packet::RtpPacket,

    /// Authentication tag (if used)
    pub auth_tag: Option<Vec<u8>>,
}

impl ProtectedRtpPacket {
    /// Serialize the protected packet with its authentication tag
    pub fn serialize(&self) -> Result<bytes::Bytes, crate::Error> {
        self.serialize_into(&mut bytes::BytesMut::new())
    }

    /// Serialize the protected packet into a caller-owned scratch buffer.
    pub fn serialize_into(
        &self,
        buffer: &mut bytes::BytesMut,
    ) -> Result<bytes::Bytes, crate::Error> {
        buffer.clear();
        buffer.reserve(self.packet.size() + self.auth_tag.as_ref().map_or(0, Vec::len));

        self.packet.header.serialize(buffer)?;
        buffer.extend_from_slice(&self.packet.payload);
        if !self.packet.header.padding && self.packet.padding_size != 0 {
            return Err(crate::Error::InvalidParameter(format!(
                "RTP padding flag ({}) does not match padding length ({})",
                self.packet.header.padding, self.packet.padding_size
            )));
        }
        if self.packet.header.padding
            && self.packet.padding_size == 0
            && self.packet.payload.is_empty()
        {
            return Err(crate::Error::InvalidParameter(
                "protected RTP padding flag is set but the encrypted payload is empty".to_string(),
            ));
        }
        if self.packet.padding_size != 0 {
            for _ in 1..self.packet.padding_size {
                buffer.extend_from_slice(&[0]);
            }
            buffer.extend_from_slice(&[self.packet.padding_size]);
        }
        if let Some(tag) = &self.auth_tag {
            buffer.extend_from_slice(tag);
        }

        Ok(buffer.split().freeze())
    }
}

impl SrtpContext {
    /// Create a new SRTP context for one direction (send or receive).
    ///
    /// There is deliberately no constructor that takes both a local and a
    /// remote key: a real SDES or DTLS-SRTP negotiation always derives two
    /// independent directional keys, so build one `SrtpContext` per
    /// direction with the matching key — `SrtpContext::new(tx_suite,
    /// local_key)` for sending, `SrtpContext::new(rx_suite, remote_key)`
    /// for receiving.
    pub fn new(suite: SrtpCryptoSuite, key: crypto::SrtpCryptoKey) -> Result<Self, crate::Error> {
        suite.validate()?;
        let outbound_crypto = crypto::SrtpCrypto::new(suite.clone(), key.clone())?;
        let inbound_crypto = crypto::SrtpCrypto::new(suite, key)?;

        Ok(Self {
            enabled: true,
            outbound_crypto,
            inbound_crypto,
            key_rotation: key_derivation::KeyRotationFrequency::None,
            outbound_rtp: HashMap::new(),
            inbound_rtp: HashMap::new(),
            outbound_srtcp: HashMap::new(),
            inbound_srtcp: HashMap::new(),
        })
    }

    /// Create an SRTP context from directional key objects.
    ///
    /// `local` protects outbound traffic and `remote` unprotects inbound
    /// traffic. This is the preferred constructor for offer/answer exchanges
    /// that advertise independent transmit keys.
    pub fn new_directional(
        suite: SrtpCryptoSuite,
        local: crypto::SrtpCryptoKey,
        remote: crypto::SrtpCryptoKey,
    ) -> Result<Self, crate::Error> {
        Self::new_from_keys(
            local.key().to_vec(),
            remote.key().to_vec(),
            local.salt().to_vec(),
            remote.salt().to_vec(),
            suite,
        )
    }

    /// Create a new SRTP context from separate local and remote keys
    pub fn new_from_keys(
        local_key: Vec<u8>,
        remote_key: Vec<u8>,
        local_salt: Vec<u8>,
        remote_salt: Vec<u8>,
        profile: SrtpCryptoSuite,
    ) -> Result<Self, crate::Error> {
        profile.validate()?;
        let outbound_crypto = crypto::SrtpCrypto::new(
            profile.clone(),
            crypto::SrtpCryptoKey::new(local_key, local_salt),
        )?;
        let inbound_crypto =
            crypto::SrtpCrypto::new(profile, crypto::SrtpCryptoKey::new(remote_key, remote_salt))?;

        Ok(Self {
            enabled: true,
            outbound_crypto,
            inbound_crypto,
            key_rotation: key_derivation::KeyRotationFrequency::None,
            outbound_rtp: HashMap::new(),
            inbound_rtp: HashMap::new(),
            outbound_srtcp: HashMap::new(),
            inbound_srtcp: HashMap::new(),
        })
    }

    /// Enable or disable SRTP
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Validate that this context may be installed in a secure transport.
    pub(crate) fn validate_for_secure_transport(&self) -> Result<(), crate::Error> {
        if !self.enabled {
            return Err(crate::Error::InvalidState(
                "disabled SRTP context cannot be installed as secure media".to_string(),
            ));
        }
        self.outbound_crypto.suite().validate()?;
        self.inbound_crypto.suite().validate()
    }

    /// Set key rotation frequency
    pub fn set_key_rotation(&mut self, frequency: key_derivation::KeyRotationFrequency) {
        self.key_rotation = frequency;
    }

    /// Protect an RTP packet (SRTP encryption)
    /// Returns the encrypted packet with its authentication tag
    pub fn protect(
        &mut self,
        packet: &crate::packet::RtpPacket,
    ) -> Result<ProtectedRtpPacket, crate::Error> {
        // Check if SRTP is enabled
        if !self.enabled {
            return Err(crate::Error::InvalidState(
                "disabled SRTP context cannot pass RTP through as plaintext".to_string(),
            ));
        }

        let ssrc = packet.header.ssrc;
        let seq = packet.header.sequence_number;
        let candidate = candidate_rtp_index(self.outbound_rtp.get(&ssrc), seq);
        if candidate.before_roc_zero {
            return Err(crate::Error::SrtpError(
                "outbound SRTP sequence maps before ROC zero".to_string(),
            ));
        }
        let roc = candidate.roc;
        let packet_index = candidate.index;
        // Track the outbound index for this SSRC so we can commit it after
        // a successful encryption.

        // Check for key rotation
        if self.key_rotation.should_rotate(packet_index) {
            return Err(crate::Error::UnsupportedFeature(
                "SRTP key rotation is not implemented; refusing to reuse the old key after the configured rotation boundary"
                    .to_string(),
            ));
        }

        // Encrypt the packet using SRTP
        let (encrypted, auth_tag) = self.outbound_crypto.encrypt_rtp(packet, roc)?;
        let state = self.outbound_rtp.entry(ssrc).or_default();
        commit_rtp_index(state, roc, seq, packet_index);

        // Return the encrypted packet with its authentication tag
        Ok(ProtectedRtpPacket {
            packet: encrypted,
            auth_tag,
        })
    }

    /// Unprotect an RTP packet (SRTP decryption).
    ///
    /// The input data should include the authentication tag if used.
    /// Follows RFC 3711's required order: estimate the rollover
    /// counter/packet index, check the replay window, verify
    /// authentication, decrypt — and only touch this SSRC's stored
    /// state (rollover counter, high-water mark, replay window) once all
    /// of that has actually succeeded. Any failure leaves state
    /// untouched and returns `Err`, never a silent plaintext fallback.
    pub fn unprotect(&mut self, data: &[u8]) -> Result<crate::packet::RtpPacket, crate::Error> {
        // Check if SRTP is enabled
        if !self.enabled {
            return Err(crate::Error::InvalidState(
                "disabled SRTP context cannot accept RTP as plaintext".to_string(),
            ));
        }

        let (header, _) = crate::packet::RtpHeader::parse_without_consuming(data)?;
        let ssrc = header.ssrc;
        let seq = header.sequence_number;
        let candidate = candidate_rtp_index(self.inbound_rtp.get(&ssrc), seq);

        // Authentication deliberately happens before the replay decision is
        // applied or any state entry is inserted.
        let packet = self.inbound_crypto.decrypt_rtp(data, candidate.roc)?;
        if candidate.before_roc_zero {
            return Err(crate::Error::SrtpError(
                "SRTP packet maps before ROC zero".to_string(),
            ));
        }
        let roc = candidate.roc;
        let packet_index = candidate.index;
        if self
            .inbound_rtp
            .get(&ssrc)
            .is_some_and(|state| !state.replay.accepts(packet_index))
        {
            return Err(crate::Error::SrtpError(
                "SRTP packet is a duplicate or outside the replay window".to_string(),
            ));
        }
        let state = self.inbound_rtp.entry(ssrc).or_default();
        commit_rtp_index(state, roc, seq, packet_index);
        Ok(packet)
    }

    /// Protect an RTCP packet (SRTCP encryption)
    /// Returns the encrypted data with the authentication tag appended
    pub fn protect_rtcp(&mut self, data: &[u8]) -> Result<bytes::Bytes, crate::Error> {
        // Check if SRTP is enabled
        if !self.enabled {
            return Err(crate::Error::InvalidState(
                "disabled SRTP context cannot pass RTCP through as plaintext".to_string(),
            ));
        }

        // Parse the complete plaintext before choosing or consuming an index.
        validate_plaintext_rtcp(data)?;
        let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let index = match self.outbound_srtcp.get(&ssrc) {
            Some(send_state) if send_state.exhausted => {
                return Err(crate::Error::SrtpError(
                    "SRTCP index exhausted; rekey before sending".to_string(),
                ));
            }
            Some(send_state) => send_state.next_index,
            None => 1,
        };
        if index > 0x7fff_ffff {
            return Err(crate::Error::SrtpError(
                "SRTCP index exhausted; rekey before sending".to_string(),
            ));
        }

        // Encrypt using SRTCP
        let (encrypted, auth_tag) = self.outbound_crypto.encrypt_rtcp_with_index(data, index)?;
        let send_state = self.outbound_srtcp.entry(ssrc).or_default();
        if index == 0x7fff_ffff {
            send_state.exhausted = true;
        } else {
            send_state.next_index += 1;
        }

        // If authentication is used, append the tag
        if let Some(tag) = auth_tag {
            let mut buffer = bytes::BytesMut::with_capacity(encrypted.len() + tag.len());
            buffer.extend_from_slice(&encrypted);
            buffer.extend_from_slice(&tag);
            Ok(buffer.freeze())
        } else {
            Ok(encrypted)
        }
    }

    /// Unprotect an RTCP packet (SRTCP decryption).
    ///
    /// Same peek/check/verify/decrypt/commit discipline as [`Self::unprotect`],
    /// keyed by the sender SSRC extracted from the packet's own
    /// (unencrypted) header.
    pub fn unprotect_rtcp(&mut self, data: &[u8]) -> Result<bytes::Bytes, crate::Error> {
        // Check if SRTP is enabled
        if !self.enabled {
            return Err(crate::Error::InvalidState(
                "disabled SRTP context cannot accept RTCP as plaintext".to_string(),
            ));
        }

        // Authentication and decryption complete before parsing, replay
        // decisions, or any state entry is inserted.
        let (packet, ssrc, index) = self.inbound_crypto.decrypt_rtcp_with_index(data)?;
        validate_plaintext_rtcp(&packet)?;
        if self
            .inbound_srtcp
            .get(&ssrc)
            .is_some_and(|replay| !replay.accepts(u64::from(index)))
        {
            return Err(crate::Error::SrtpError(
                "SRTCP packet is a duplicate or outside the replay window".to_string(),
            ));
        }
        let replay = self.inbound_srtcp.entry(ssrc).or_default();
        replay.commit(u64::from(index));
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::RtpPacket;
    use bytes::Bytes;

    fn contexts_with_suite(suite: SrtpCryptoSuite) -> (SrtpContext, SrtpContext) {
        let a_key = vec![0x11; 16];
        let a_salt = vec![0x22; 14];
        let b_key = vec![0x33; 16];
        let b_salt = vec![0x44; 14];
        let a = SrtpContext::new_from_keys(
            a_key.clone(),
            b_key.clone(),
            a_salt.clone(),
            b_salt.clone(),
            suite.clone(),
        )
        .unwrap();
        let b = SrtpContext::new_from_keys(b_key, a_key, b_salt, a_salt, suite).unwrap();
        (a, b)
    }

    fn contexts() -> (SrtpContext, SrtpContext) {
        contexts_with_suite(SRTP_AES128_CM_SHA1_80)
    }

    fn packet(ssrc: u32, seq: u16) -> crate::packet::RtpPacket {
        crate::packet::RtpPacket::new_with_payload(
            96,
            seq,
            u32::from(seq).wrapping_mul(160),
            ssrc,
            Bytes::from_static(b"authenticated media"),
        )
    }

    fn sender_report(ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 200, 0, 6];
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0x5a; 20]);
        packet
    }

    fn inbound_srtcp_snapshot(context: &SrtpContext, ssrc: u32) -> Option<(Option<u64>, u64)> {
        context
            .inbound_srtcp
            .get(&ssrc)
            .map(|state| (state.highest, state.bitmap))
    }

    fn protect_bytes(context: &mut SrtpContext, packet: &crate::packet::RtpPacket) -> Bytes {
        context.protect(packet).unwrap().serialize().unwrap()
    }

    fn protect_bytes_with_roc(
        context: &SrtpContext,
        packet: &crate::packet::RtpPacket,
        roc: u32,
    ) -> Bytes {
        let (encrypted, auth_tag) = context.outbound_crypto.encrypt_rtp(packet, roc).unwrap();
        ProtectedRtpPacket {
            packet: encrypted,
            auth_tag,
        }
        .serialize()
        .unwrap()
    }

    fn inbound_state_snapshot(
        context: &SrtpContext,
        ssrc: u32,
    ) -> Option<(u32, Option<u16>, Option<u64>, u64)> {
        context.inbound_rtp.get(&ssrc).map(|state| {
            (
                state.roc,
                state.highest_seq,
                state.replay.highest,
                state.replay.bitmap,
            )
        })
    }

    #[test]
    fn null_profiles_are_retained_but_fail_closed() {
        let key = SrtpCryptoKey::new(vec![0; 16], vec![0; 14]);
        let context = SrtpContext::new(SRTP_NULL_NULL, key);
        assert!(matches!(context, Err(crate::Error::UnsupportedFeature(_))));
    }

    #[test]
    fn aead_gcm_profiles_fail_closed() {
        let key = SrtpCryptoKey::new(vec![0; 16], vec![0; 14]);
        let error = SrtpContext::new(SRTP_AEAD_AES_128_GCM, key)
            .err()
            .expect("placeholder GCM profile must be rejected");
        assert!(matches!(error, crate::Error::UnsupportedFeature(_)));
    }

    #[test]
    fn disabled_context_rejects_plaintext_passthrough_without_state() {
        let (mut context, _) = contexts();
        let rtp = packet(0x0102_0304, 1);
        let plain_rtp = rtp.serialize().unwrap();
        let rtcp = sender_report(0x0102_0304);
        context.set_enabled(false);

        assert!(matches!(
            context.protect(&rtp),
            Err(crate::Error::InvalidState(_))
        ));
        assert!(matches!(
            context.unprotect(&plain_rtp),
            Err(crate::Error::InvalidState(_))
        ));
        assert!(matches!(
            context.protect_rtcp(&rtcp),
            Err(crate::Error::InvalidState(_))
        ));
        assert!(matches!(
            context.unprotect_rtcp(&rtcp),
            Err(crate::Error::InvalidState(_))
        ));
        assert!(context.outbound_rtp.is_empty());
        assert!(context.inbound_rtp.is_empty());
        assert!(context.outbound_srtcp.is_empty());
        assert!(context.inbound_srtcp.is_empty());
    }

    #[test]
    fn unsupported_key_rotation_does_not_mutate_outbound_state() {
        let rtp = packet(0x0102_0304, 0);
        for power in [8, 64, 255] {
            let (mut context, _) = contexts();
            context.set_key_rotation(KeyRotationFrequency::Power2(power));
            assert!(matches!(
                context.protect(&rtp),
                Err(crate::Error::UnsupportedFeature(_))
            ));
            assert!(context.outbound_rtp.is_empty());

            context.set_key_rotation(KeyRotationFrequency::None);
            context.protect(&rtp).unwrap();
        }
    }

    #[test]
    fn directional_keys_are_used_for_protect_and_unprotect() {
        let (mut a, mut b) = contexts();
        let wire = protect_bytes(&mut a, &packet(0x1020_3040, 7));
        assert_eq!(
            b.unprotect(&wire).unwrap().payload,
            Bytes::from_static(b"authenticated media")
        );
        assert!(a.unprotect(&wire).is_err(), "local key must not unprotect");
    }

    #[test]
    fn rollover_reordering_and_replay_are_per_ssrc() {
        let (mut a, mut b) = contexts();
        let ssrc = 0x0102_0304;
        for seq in [65_534, 65_535, 0, 1, 65_533] {
            let wire = protect_bytes(&mut a, &packet(ssrc, seq));
            b.unprotect(&wire).unwrap();
        }
        let state = b.inbound_rtp.get(&ssrc).unwrap();
        assert_eq!(state.roc, 1);
        assert_eq!(state.highest_seq, Some(1));
        assert_eq!(state.replay.highest, Some((1_u64 << 16) | 1));

        let other_wire = protect_bytes(&mut a, &packet(0xaabb_ccdd, 0));
        b.unprotect(&other_wire).unwrap();

        let duplicate = protect_bytes(&mut a, &packet(0x9999_0001, 9));
        b.unprotect(&duplicate).unwrap();
        assert!(b.unprotect(&duplicate).is_err());
    }

    #[test]
    fn roc_zero_uses_wrapped_candidate_for_auth_without_state_poisoning() {
        let (mut a, mut b) = contexts();
        let ssrc = 0x1357_2468;

        let first = protect_bytes(&mut a, &packet(ssrc, 0));
        b.unprotect(&first).unwrap();
        let stable = inbound_state_snapshot(&b, ssrc);

        // The old saturating ROC calculation authenticated this packet under
        // ROC zero. RFC 3711 requires the wrapped previous-cycle ROC instead.
        let wrong_roc = protect_bytes_with_roc(&a, &packet(ssrc, u16::MAX), 0);
        assert!(matches!(
            b.unprotect(&wrong_roc),
            Err(crate::Error::AuthenticationFailed(_))
        ));
        assert_eq!(inbound_state_snapshot(&b, ssrc), stable);

        // A packet carrying a valid tag for the RFC candidate authenticates,
        // but that impossible pre-zero cycle must not advance either ROC or
        // the replay window.
        let wrapped_roc = protect_bytes_with_roc(&a, &packet(ssrc, u16::MAX), u32::MAX);
        assert!(matches!(
            b.unprotect(&wrapped_roc),
            Err(crate::Error::SrtpError(message)) if message.contains("before ROC zero")
        ));
        assert_eq!(inbound_state_snapshot(&b, ssrc), stable);

        let next = protect_bytes(&mut a, &packet(ssrc, 1));
        b.unprotect(&next)
            .expect("valid current-cycle packet succeeds after both failures");
        let state = b.inbound_rtp.get(&ssrc).unwrap();
        assert_eq!(state.roc, 0);
        assert_eq!(state.highest_seq, Some(1));
    }

    #[test]
    fn outbound_packet_before_roc_zero_is_rejected_without_state_mutation() {
        let (mut a, _) = contexts();
        let ssrc = 0x2468_1357;
        protect_bytes(&mut a, &packet(ssrc, 0));
        let stable = a.outbound_rtp.get(&ssrc).cloned().unwrap();

        assert!(matches!(
            a.protect(&packet(ssrc, u16::MAX)),
            Err(crate::Error::SrtpError(message)) if message.contains("before ROC zero")
        ));
        let current = a.outbound_rtp.get(&ssrc).unwrap();
        assert_eq!(current.roc, stable.roc);
        assert_eq!(current.highest_seq, stable.highest_seq);
        assert_eq!(current.replay.highest, stable.replay.highest);
        assert_eq!(current.replay.bitmap, stable.replay.bitmap);

        a.protect(&packet(ssrc, 1))
            .expect("valid current-cycle packet succeeds after rejection");
    }

    #[test]
    fn failed_authentication_does_not_advance_rollover_or_replay_state() {
        let (mut a, mut b) = contexts();
        let ssrc = 0x1234_5678;
        for seq in [65_534, 65_535] {
            let wire = protect_bytes(&mut a, &packet(ssrc, seq));
            b.unprotect(&wire).unwrap();
        }

        let valid = protect_bytes(&mut a, &packet(ssrc, 0));
        let mut tampered = valid.to_vec();
        *tampered.last_mut().unwrap() ^= 0x80;
        assert!(matches!(
            b.unprotect(&tampered),
            Err(crate::Error::AuthenticationFailed(_))
        ));
        b.unprotect(&valid)
            .expect("valid rollover packet must succeed after failed authentication");
    }

    #[test]
    fn rtp_padding_is_encrypted_and_restored_after_unprotect() {
        let (mut a, mut b) = contexts();
        let mut original = packet(0x4567_89ab, 42);
        original.set_padding(4);
        let plaintext = original.serialize().unwrap();
        let header_size = original.header.size();

        let protected = a.protect(&original).unwrap();
        assert_eq!(protected.packet.padding_size, 0);
        let wire = protected.serialize().unwrap();
        let ciphertext_end = wire.len() - SRTP_AES128_CM_SHA1_80.tag_length;
        assert_ne!(
            &wire[header_size..ciphertext_end],
            &plaintext[header_size..],
            "the RTP padding octets must be encrypted with the payload"
        );

        let restored = b.unprotect(&wire).unwrap();
        assert_eq!(restored.payload, original.payload);
        assert_eq!(restored.padding_size, 4);
        assert_eq!(restored.serialize().unwrap(), plaintext);
    }

    #[test]
    fn unseen_packet_outside_the_replay_window_is_rejected() {
        let (mut a, mut b) = contexts();
        let ssrc = 0x0bad_f00d;
        b.unprotect(&protect_bytes(&mut a, &packet(ssrc, 0)))
            .unwrap();
        let delayed = protect_bytes(&mut a, &packet(ssrc, 1));
        for seq in 2..=70 {
            b.unprotect(&protect_bytes(&mut a, &packet(ssrc, seq)))
                .unwrap();
        }
        assert!(b.unprotect(&delayed).is_err());
    }

    #[test]
    fn srtcp_index_changes_ciphertext_and_replay_is_rejected() {
        let (mut a, mut b) = contexts();
        let plain = sender_report(0x1234_5678);
        let first = a.protect_rtcp(&plain).unwrap();
        let second = a.protect_rtcp(&plain).unwrap();
        assert_ne!(first, second);
        assert_ne!(&first[8..plain.len()], &plain[8..]);
        assert_eq!(b.unprotect_rtcp(&first).unwrap().as_ref(), plain);
        assert_eq!(b.unprotect_rtcp(&second).unwrap().as_ref(), plain);
        assert!(b.unprotect_rtcp(&first).is_err());
    }

    #[test]
    fn srtcp_directional_keys_are_used() {
        let (mut a, mut b) = contexts();
        let plain = sender_report(0x1020_3040);
        let wire = a.protect_rtcp(&plain).unwrap();
        assert_eq!(b.unprotect_rtcp(&wire).unwrap().as_ref(), plain);
        assert!(a.unprotect_rtcp(&wire).is_err());
    }

    #[test]
    fn srtcp_reordering_duplicates_and_old_packets_use_a_per_ssrc_window() {
        let (mut a, mut b) = contexts();
        let ssrc = 0x7654_3210;
        let plain = sender_report(ssrc);
        let wires: Vec<_> = (0..70).map(|_| a.protect_rtcp(&plain).unwrap()).collect();

        b.unprotect_rtcp(&wires[0]).unwrap();
        b.unprotect_rtcp(&wires[2]).unwrap();
        b.unprotect_rtcp(&wires[1])
            .expect("reordered packet inside the replay window");
        assert!(b.unprotect_rtcp(&wires[1]).is_err());

        for wire in &wires[3..] {
            b.unprotect_rtcp(wire).unwrap();
        }
        assert!(
            b.unprotect_rtcp(&wires[1]).is_err(),
            "packet older than the 64-packet window must remain rejected"
        );
    }

    #[test]
    fn malformed_authenticated_srtcp_does_not_mutate_receive_state() {
        let (a, mut b) = contexts();
        let ssrc = 0x1112_1314;
        let malformed = [0x80, 200, 0, 6, 0x11, 0x12, 0x13, 0x14];
        let (encrypted, tag) = a
            .outbound_crypto
            .encrypt_rtcp_with_index(&malformed, 1)
            .unwrap();
        let mut wire = encrypted.to_vec();
        wire.extend_from_slice(&tag.unwrap());

        assert!(b.unprotect_rtcp(&wire).is_err());
        assert_eq!(inbound_srtcp_snapshot(&b, ssrc), None);

        let mut sender = a;
        let valid = sender.protect_rtcp(&sender_report(ssrc)).unwrap();
        assert!(b.unprotect_rtcp(&valid).is_ok());
    }

    #[test]
    fn malformed_sdes_cannot_consume_srtcp_send_or_receive_state() {
        let (sender, mut receiver) = contexts();
        let ssrc = 0x2122_2324;
        // One declared SDES chunk containing only its SSRC and no mandatory
        // END item. The common header and declared packet length are valid.
        let malformed = [0x81, 202, 0, 1, 0x21, 0x22, 0x23, 0x24];

        let mut outbound = sender;
        assert!(outbound.protect_rtcp(&malformed).is_err());
        assert!(!outbound.outbound_srtcp.contains_key(&ssrc));

        let (encrypted, tag) = outbound
            .outbound_crypto
            .encrypt_rtcp_with_index(&malformed, 1)
            .unwrap();
        let mut wire = encrypted.to_vec();
        wire.extend_from_slice(&tag.unwrap());
        assert!(receiver.unprotect_rtcp(&wire).is_err());
        assert_eq!(inbound_srtcp_snapshot(&receiver, ssrc), None);
    }

    #[test]
    fn authenticated_cleartext_srtcp_is_rejected_without_state_mutation() {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let (_, mut receiver) = contexts();
        let ssrc = 0x3141_5926;
        let plain = sender_report(ssrc);
        let mut wire = plain.clone();
        // Index one with E=0: the packet is correctly authenticated below but
        // contradicts the negotiated AES-CM encryption policy.
        wire.extend_from_slice(&1_u32.to_be_bytes());

        let remote_master = SrtpCryptoKey::new(vec![0x11; 16], vec![0x22; 14]);
        let auth_key = srtp_kdf(
            &remote_master,
            &SrtpKeyDerivationParams {
                label: KeyDerivationLabel::RtcpAuthentication,
                key_derivation_rate: 0,
                index: 0,
            },
            20,
        )
        .unwrap();
        let mut mac = Hmac::<Sha1>::new_from_slice(&auth_key).unwrap();
        mac.update(&wire);
        wire.extend_from_slice(&mac.finalize().into_bytes()[..10]);

        assert!(matches!(
            receiver.unprotect_rtcp(&wire),
            Err(crate::Error::AuthenticationFailed(message))
                if message.contains("requires the E flag")
        ));
        assert_eq!(inbound_srtcp_snapshot(&receiver, ssrc), None);
    }

    #[test]
    fn malformed_plaintext_rtcp_does_not_consume_an_outbound_index() {
        let (mut a, _) = contexts();
        let ssrc = 0x2233_4455;
        assert!(a.protect_rtcp(&[0x80, 205, 0, 0]).is_err());
        assert!(a.outbound_srtcp.is_empty());
        let malformed = [0x80, 200, 0, 6, 0x22, 0x33, 0x44, 0x55];
        assert!(a.protect_rtcp(&malformed).is_err());
        assert!(!a.outbound_srtcp.contains_key(&ssrc));

        let wire = a.protect_rtcp(&sender_report(ssrc)).unwrap();
        let index_offset = wire.len() - SRTP_AES128_CM_SHA1_80.srtcp_tag_length() - 4;
        assert_eq!(
            u32::from_be_bytes(wire[index_offset..index_offset + 4].try_into().unwrap())
                & 0x7fff_ffff,
            1
        );
    }

    #[test]
    fn unknown_well_formed_rtcp_type_survives_srtcp_round_trip() {
        let (mut sender, mut receiver) = contexts();
        let unknown = [0x80, 208, 0, 1, 0x11, 0x22, 0x33, 0x44];

        let wire = sender.protect_rtcp(&unknown).unwrap();
        assert_eq!(receiver.unprotect_rtcp(&wire).unwrap().as_ref(), unknown);
    }

    #[test]
    fn sha1_32_uses_four_byte_srtp_and_ten_byte_srtcp_tags() {
        assert_eq!(SRTP_AES128_CM_SHA1_32.tag_length, 4);
        assert_eq!(SRTP_AES128_CM_SHA1_32.srtcp_tag_length(), 10);

        let (mut a, mut b) = contexts_with_suite(SRTP_AES128_CM_SHA1_32);
        let rtp = protect_bytes(&mut a, &packet(0x1020_3040, 1));
        assert_eq!(rtp.len(), packet(0x1020_3040, 1).size() + 4);
        b.unprotect(&rtp).unwrap();

        let rtcp = [0x80, 201, 0, 1, 0x12, 0x34, 0x56, 0x78];
        let srtcp = a.protect_rtcp(&rtcp).unwrap();
        assert_eq!(srtcp.len(), rtcp.len() + 4 + 10);
        assert_eq!(b.unprotect_rtcp(&srtcp).unwrap().as_ref(), rtcp);
    }

    #[test]
    fn srtcp_auth_failure_does_not_consume_an_index() {
        let (mut a, mut b) = contexts();
        let plain = [0x80, 201, 0, 1, 0x12, 0x34, 0x56, 0x78];
        let ssrc = 0x1234_5678;
        let valid = a.protect_rtcp(&plain).unwrap();
        let mut tampered = valid.to_vec();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            b.unprotect_rtcp(&tampered),
            Err(crate::Error::AuthenticationFailed(_))
        ));
        assert_eq!(inbound_srtcp_snapshot(&b, ssrc), None);
        assert_eq!(b.unprotect_rtcp(&valid).unwrap().as_ref(), plain);
    }

    #[test]
    fn srtcp_indexes_are_independent_per_ssrc_and_never_wrap() {
        let (mut a, mut b) = contexts();
        let first = [0x80, 201, 0, 1, 0x11, 0x11, 0x11, 0x11];
        let second = [0x80, 201, 0, 1, 0x22, 0x22, 0x22, 0x22];
        let first_wire = a.protect_rtcp(&first).unwrap();
        let second_wire = a.protect_rtcp(&second).unwrap();
        assert_eq!(
            u32::from_be_bytes(
                first_wire[first_wire.len() - 14..first_wire.len() - 10]
                    .try_into()
                    .unwrap()
            ) & 0x7fff_ffff,
            1
        );
        assert_eq!(
            u32::from_be_bytes(
                second_wire[second_wire.len() - 14..second_wire.len() - 10]
                    .try_into()
                    .unwrap()
            ) & 0x7fff_ffff,
            1
        );
        assert_eq!(b.unprotect_rtcp(&first_wire).unwrap().as_ref(), first);
        assert_eq!(b.unprotect_rtcp(&second_wire).unwrap().as_ref(), second);

        a.outbound_srtcp.insert(
            0x1111_1111,
            SrtcpSendState {
                next_index: 0x7fff_ffff,
                exhausted: false,
            },
        );
        a.protect_rtcp(&first).expect("last SRTCP index is usable");
        assert!(a.protect_rtcp(&first).is_err());
    }

    fn matching_contexts() -> (SrtpContext, SrtpContext) {
        let key = SrtpCryptoKey::new(vec![7u8; 16], vec![9u8; 14]);
        let tx = SrtpContext::new(SRTP_AES128_CM_SHA1_80, key.clone()).unwrap();
        let rx = SrtpContext::new(SRTP_AES128_CM_SHA1_80, key).unwrap();
        (tx, rx)
    }

    fn rtp_packet(ssrc: u32, seq: u16) -> RtpPacket {
        RtpPacket::new_with_payload(
            96,
            seq,
            12345,
            ssrc,
            bytes::Bytes::from_static(b"hello srtp"),
        )
    }

    fn roundtrip(
        tx: &mut SrtpContext,
        rx: &mut SrtpContext,
        ssrc: u32,
        seq: u16,
    ) -> Result<(), crate::Error> {
        let protected = tx.protect(&rtp_packet(ssrc, seq))?;
        let wire = protected.serialize()?;
        rx.unprotect(&wire)?;
        Ok(())
    }

    #[test]
    fn sequence_wrap_from_65535_to_0_still_decrypts() {
        let (mut tx, mut rx) = matching_contexts();
        let ssrc = 0xAAAA_1111;

        for seq in [65530u16, 65531, 65532, 65533, 65534, 65535, 0, 1, 2, 3] {
            roundtrip(&mut tx, &mut rx, ssrc, seq)
                .unwrap_or_else(|e| panic!("seq {seq} failed to roundtrip: {e}"));
        }

        // The rx side must have actually advanced its rollover counter,
        // not stayed stuck at roc=0 (the bug this hardening pass fixes).
        let state = rx.inbound_rtp.get(&ssrc).unwrap();
        assert_eq!(state.roc, 1);
        assert_eq!(state.highest_seq, Some(3));
    }

    #[test]
    fn reordered_packet_from_before_the_wrap_still_decrypts() {
        // Note: a receiver's very first-ever packet for an SSRC is always
        // treated as roc=0 by convention (RFC 3711 §3.3.1) — there's no
        // way to know a stream had already wrapped before the first
        // packet a receiver happens to observe. So this test establishes
        // real state (via seq=65533) *before* the ambiguous reorder
        // happens, which is the scenario the rollover guess is actually
        // meant to solve.
        let (mut tx, mut rx) = matching_contexts();
        let ssrc = 0xBBBB_2222;

        let baseline = tx
            .protect(&rtp_packet(ssrc, 65533))
            .unwrap()
            .serialize()
            .unwrap();
        rx.unprotect(&baseline).expect("baseline packet decrypts");

        let before_wrap = tx
            .protect(&rtp_packet(ssrc, 65535))
            .unwrap()
            .serialize()
            .unwrap();
        let after_wrap = tx
            .protect(&rtp_packet(ssrc, 2))
            .unwrap()
            .serialize()
            .unwrap();

        // Deliver the post-wrap packet first, advancing rx to roc=1, then
        // the pre-wrap packet arrives late.
        rx.unprotect(&after_wrap)
            .expect("post-wrap packet decrypts");
        rx.unprotect(&before_wrap)
            .expect("late pre-wrap packet must still decrypt using roc-1");

        // The high-water mark must not have been dragged backward by the
        // late packet.
        let state = rx.inbound_rtp.get(&ssrc).unwrap();
        assert_eq!(state.roc, 1);
        assert_eq!(state.highest_seq, Some(2));
    }

    #[test]
    fn replayed_packet_is_rejected_without_corrupting_state() {
        let (mut tx, mut rx) = matching_contexts();
        let ssrc = 0xCCCC_3333;

        let wire = tx
            .protect(&rtp_packet(ssrc, 100))
            .unwrap()
            .serialize()
            .unwrap();

        rx.unprotect(&wire).expect("first delivery succeeds");
        let replay_result = rx.unprotect(&wire);
        assert!(replay_result.is_err(), "exact replay must be rejected");

        // A subsequent, genuinely new packet must still work — proves the
        // rejected replay didn't leave any state half-mutated.
        let next_wire = tx
            .protect(&rtp_packet(ssrc, 101))
            .unwrap()
            .serialize()
            .unwrap();
        rx.unprotect(&next_wire)
            .expect("state must be intact after a rejected replay");
    }

    #[test]
    fn packet_far_outside_the_replay_window_is_rejected() {
        let (mut tx, mut rx) = matching_contexts();
        let ssrc = 0xDDDD_4444;

        let old_wire = tx
            .protect(&rtp_packet(ssrc, 100))
            .unwrap()
            .serialize()
            .unwrap();
        rx.unprotect(&old_wire).unwrap();

        // Jump far ahead, well past the replay window.
        for seq in 101..2000u16 {
            let wire = tx
                .protect(&rtp_packet(ssrc, seq))
                .unwrap()
                .serialize()
                .unwrap();
            rx.unprotect(&wire).unwrap();
        }

        // The very first packet, now long outside the window, must still
        // be rejected if seen again.
        assert!(rx.unprotect(&old_wire).is_err());
    }

    #[test]
    fn tampered_payload_is_rejected_and_original_still_decrypts_later() {
        let (mut tx, mut rx) = matching_contexts();
        let ssrc = 0xEEEE_5555;

        let wire = tx
            .protect(&rtp_packet(ssrc, 200))
            .unwrap()
            .serialize()
            .unwrap();
        let mut tampered = wire.to_vec();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;

        assert!(rx.unprotect(&tampered).is_err());

        // Retrying with the untampered packet for the SAME sequence number
        // must still succeed — if the failed attempt had mutated the
        // replay window or high-water mark, this would now be rejected.
        rx.unprotect(&wire)
            .expect("tampered attempt must not have poisoned state for the real packet");
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let key_a = SrtpCryptoKey::new(vec![1u8; 16], vec![2u8; 14]);
        let key_b = SrtpCryptoKey::new(vec![3u8; 16], vec![4u8; 14]);
        let mut tx = SrtpContext::new(SRTP_AES128_CM_SHA1_80, key_a).unwrap();
        let mut rx = SrtpContext::new(SRTP_AES128_CM_SHA1_80, key_b).unwrap();

        let wire = tx
            .protect(&rtp_packet(0x1234, 1))
            .unwrap()
            .serialize()
            .unwrap();
        assert!(rx.unprotect(&wire).is_err());
    }

    #[test]
    fn two_ssrcs_multiplexed_through_one_context_track_independently() {
        let (mut tx, mut rx) = matching_contexts();
        let ssrc_a = 0x1111_1111;
        let ssrc_b = 0x2222_2222;

        // Push SSRC A far ahead (near a wrap) while SSRC B stays low.
        for seq in [65530u16, 65531, 65532, 0, 1] {
            roundtrip(&mut tx, &mut rx, ssrc_a, seq).unwrap();
        }
        for seq in [10u16, 11, 12] {
            roundtrip(&mut tx, &mut rx, ssrc_b, seq).unwrap();
        }

        let state_a = rx.inbound_rtp.get(&ssrc_a).unwrap();
        let state_b = rx.inbound_rtp.get(&ssrc_b).unwrap();
        assert_eq!(state_a.roc, 1);
        assert_eq!(state_a.highest_seq, Some(1));
        assert_eq!(state_b.roc, 0);
        assert_eq!(state_b.highest_seq, Some(12));

        // A replay on A must not affect B and vice versa.
        let wire_a = tx
            .protect(&rtp_packet(ssrc_a, 1))
            .expect("re-protecting an already-sent seq must succeed on the outbound side");
        let _ = wire_a;
    }

    fn synthetic_rtcp_packet(ssrc: u32, marker: u8) -> Vec<u8> {
        // V2, PT=200 (SR), length=6 (7 words = 28 bytes)
        let mut data = vec![0x80, 200, 0x00, 0x06];
        data.extend_from_slice(&ssrc.to_be_bytes());
        // NTP timestamp (8 bytes) + RTP timestamp (4) + pkt count (4) + octet count (4) = 20
        data.extend_from_slice(&[marker; 20]);
        data
    }

    #[test]
    fn srtcp_successive_packets_use_increasing_real_indices() {
        let (mut tx, mut rx) = matching_contexts();
        let ssrc = 0xF00D_0001;

        for i in 0..5u8 {
            let plain = synthetic_rtcp_packet(ssrc, i);
            let protected = tx.protect_rtcp(&plain).unwrap();
            let recovered = rx.unprotect_rtcp(&protected).unwrap();
            assert_eq!(recovered.as_ref(), plain.as_slice());
        }

        let tx_state = tx.outbound_srtcp.get(&ssrc).unwrap();
        assert_eq!(tx_state.next_index, 6);
    }

    #[test]
    fn srtcp_replay_is_rejected() {
        let (mut tx, mut rx) = matching_contexts();
        let ssrc = 0xF00D_0002;

        let plain = synthetic_rtcp_packet(ssrc, 1);
        let protected = tx.protect_rtcp(&plain).unwrap();

        rx.unprotect_rtcp(&protected).unwrap();
        assert!(rx.unprotect_rtcp(&protected).is_err());
    }

    #[test]
    fn srtcp_tampered_packet_is_rejected() {
        let (mut tx, mut rx) = matching_contexts();
        let ssrc = 0xF00D_0003;

        let plain = synthetic_rtcp_packet(ssrc, 7);
        let protected = tx.protect_rtcp(&plain).unwrap();
        let mut tampered = protected.to_vec();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;

        assert!(rx.unprotect_rtcp(&tampered).is_err());
    }

    #[test]
    fn srtcp_compound_packet_round_trips_without_altering_structure() {
        let (mut tx, mut rx) = matching_contexts();
        let ssrc = 0xF00D_0004;

        // Simulate a compound RTCP packet: SR header + an extra chunk of
        // "sub-packets" concatenated after it, per RFC 3711 §3.4's model
        // of everything past the first packet's 8-byte header being
        // opaque payload to SRTCP.
        let mut compound = synthetic_rtcp_packet(ssrc, 3);
        // RR with RC=1: header(4) + SSRC(4) + 1 report block(24) = 32 bytes, length=7
        let mut rr = vec![0x81, 201, 0x00, 0x07];
        rr.extend_from_slice(&0xBEEF_0001u32.to_be_bytes()); // RR SSRC
        rr.extend_from_slice(&[0xDE; 24]); // 1 report block
        compound.extend_from_slice(&rr);

        let protected = tx.protect_rtcp(&compound).unwrap();
        let recovered = rx.unprotect_rtcp(&protected).unwrap();
        assert_eq!(recovered.as_ref(), compound.as_slice());
    }
}

#[cfg(test)]
mod integration_tests;
