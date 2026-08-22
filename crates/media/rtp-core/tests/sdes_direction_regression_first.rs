use rvoip_rtp_core::security::sdes::SdesNegotiator;
use rvoip_rtp_core::srtp::SRTP_AES128_CM_SHA1_80;
use rvoip_rtp_core::RtpPacket;
use bytes::Bytes;

#[test]
fn sdes_answerer_generates_fresh_transmit_key_material() {
    let (offerer, offer_attrs) = SdesNegotiator::new_offerer(&[SRTP_AES128_CM_SHA1_80]).unwrap();
    let answerer = SdesNegotiator::new_answerer();

    let (answer_attr, mut answerer_pair) = answerer.process_offer(&offer_attrs).unwrap();
    let mut offerer_pair = offerer.accept_answer(&answer_attr).unwrap();

    // Each side's send context is keyed with its own independently generated
    // master key — encrypting the same plaintext must produce different
    // ciphertext.
    let probe = RtpPacket::new_with_payload(0, 1, 1, 1, Bytes::from_static(b"probe"));
    let offerer_wire = offerer_pair.send_ctx.protect(&probe).unwrap().serialize().unwrap();
    let answerer_wire = answerer_pair.send_ctx.protect(&probe).unwrap().serialize().unwrap();
    assert_ne!(
        offerer_wire, answerer_wire,
        "an SDES answer must carry fresh local transmit key material"
    );
}
