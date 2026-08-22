use crate::packet::{RtpHeader, RtpPacket};
use crate::security::sdes::SdesNegotiator;
use crate::security::SecurityKeyExchange;
use crate::srtp::{SrtpContext, SrtpCryptoKey, SRTP_AES128_CM_SHA1_80};
use bytes::Bytes;

/// Proves a real, independent offerer/answerer SDES exchange: each side
/// generates its own master key (RFC 4568 §6.1) and both directions of
/// real SRTP traffic work — not the old bug where the answerer echoed
/// the offerer's own key back, making a "two-party" test that could only
/// ever exercise one key encrypting/decrypting with itself.
#[test]
fn test_srtp_with_sdes_key_exchange() {
    // 1. Set up SDES key exchange
    let (offerer, offer_attrs) =
        SdesNegotiator::new_offerer(&[SRTP_AES128_CM_SHA1_80]).expect("offerer setup");
    let answerer = SdesNegotiator::new_answerer();

    // Answerer processes the offer and generates its own key for the answer.
    let (answer_attr, answerer_pair) = answerer
        .process_offer(&offer_attrs)
        .expect("answerer processes offer");

    // Offerer accepts the answer, decoding the answerer's independently
    // generated key.
    let offerer_pair = offerer
        .accept_answer(&answer_attr)
        .expect("offerer accepts answer");

    // 2. Use the negotiated keys with SRTP — both directions.
    let mut offerer_send = offerer_pair.send_ctx;
    let mut answerer_recv = answerer_pair.recv_ctx;

    let header = RtpHeader::new(96, 1000, 12345, 0xabcdef01);
    let payload = Bytes::from_static(b"Hello secure RTP world!");
    let packet = RtpPacket::new(header, payload.clone());

    let protected = offerer_send
        .protect(&packet)
        .expect("Failed to protect RTP packet");
    let protected_bytes = protected
        .serialize()
        .expect("Failed to serialize protected packet");
    let decrypted = answerer_recv
        .unprotect(&protected_bytes)
        .expect("Failed to unprotect RTP packet");

    assert_eq!(decrypted.header.payload_type, packet.header.payload_type);
    assert_eq!(
        decrypted.header.sequence_number,
        packet.header.sequence_number
    );
    assert_eq!(decrypted.header.timestamp, packet.header.timestamp);
    assert_eq!(decrypted.header.ssrc, packet.header.ssrc);
    assert_eq!(decrypted.payload, payload);

    // The other direction, proving the two SrtpContexts really are keyed
    // independently rather than sharing one master key.
    let mut answerer_send = answerer_pair.send_ctx;
    let mut offerer_recv = offerer_pair.recv_ctx;
    let header2 = RtpHeader::new(96, 2000, 54321, 0xface_d00d);
    let payload2 = Bytes::from_static(b"Hello back, securely.");
    let packet2 = RtpPacket::new(header2, payload2.clone());

    let protected2 = answerer_send
        .protect(&packet2)
        .expect("Failed to protect return RTP packet");
    let protected_bytes2 = protected2
        .serialize()
        .expect("Failed to serialize protected return packet");
    let decrypted2 = offerer_recv
        .unprotect(&protected_bytes2)
        .expect("Failed to unprotect return RTP packet");
    assert_eq!(decrypted2.payload, payload2);
}

#[test]
fn mikey_fails_closed_before_srtp_setup() {
    use crate::security::mikey::{Mikey, MikeyConfig, MikeyKeyExchangeMethod, MikeyRole};

    let config = MikeyConfig {
        method: MikeyKeyExchangeMethod::Psk,
        psk: Some(vec![0x31; 16]),
        srtp_profile: SRTP_AES128_CM_SHA1_80,
        ..Default::default()
    };

    assert!(matches!(
        Mikey::try_new(config.clone(), MikeyRole::Initiator),
        Err(crate::Error::UnsupportedFeature(_))
    ));

    let mut compatibility_instance = Mikey::new(config, MikeyRole::Initiator);
    assert!(matches!(
        compatibility_instance.init(),
        Err(crate::Error::UnsupportedFeature(_))
    ));
    assert!(compatibility_instance.get_srtp_key().is_none());
    assert!(compatibility_instance.get_srtp_suite().is_none());
}

#[test]
fn test_zrtp_fails_closed_before_srtp_setup() {
    use crate::security::zrtp::{Zrtp, ZrtpConfig, ZrtpRole};

    assert!(matches!(
        Zrtp::try_new(ZrtpConfig::default(), ZrtpRole::Initiator),
        Err(crate::Error::UnsupportedFeature(_))
    ));

    let mut compatibility_instance = Zrtp::new(ZrtpConfig::default(), ZrtpRole::Initiator);
    assert!(matches!(
        compatibility_instance.init(),
        Err(crate::Error::UnsupportedFeature(_))
    ));
    assert!(compatibility_instance.get_srtp_key().is_none());
    assert!(compatibility_instance.get_srtp_suite().is_none());
}
