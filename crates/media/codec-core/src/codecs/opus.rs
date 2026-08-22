//! Opus Audio Codec Implementation
//!
//! This module implements the Opus codec, a modern audio codec standardized
//! by the Internet Engineering Task Force (IETF) in RFC 6716. Opus combines
//! the best features of both speech and music codecs with very low latency.
//!
//! Two mutually-exclusive-in-intent backends live behind separate features:
//!
//! - `opus`: real encode/decode via the [`opus`](https://docs.rs/opus) crate
//!   (SpaceManiac/opus-rs), which binds the native libopus C library via
//!   `audiopus_sys`. Requires libopus (and a C toolchain) to build/link.
//!   This is what you want for actual audio - it's the same reference
//!   codebase every other libopus-based SIP/WebRTC stack uses.
//! - `opus-sim`: a deterministic stub that produces plausible-shaped output
//!   (right size, varies with bitrate) without doing any real DSP. Useful
//!   for fast, deterministic pipeline tests that don't care about audio
//!   fidelity. If both features are enabled, `opus` (real) takes priority.

use crate::error::{CodecError, Result};
use crate::types::{AudioCodec, AudioCodecExt, CodecConfig, CodecInfo, SampleRate};
use crate::utils::validate_opus_frame;
use tracing::{debug, trace};

// libopus permits callers to provide up to 4,000 bytes to one encode call.
// RFC 6716's 1,275-byte limit is per frame; a packet can contain multiple
// frames (including a 60 ms high-bitrate packet), so it is not a safe output
// buffer contract for the encoder API.
const MAX_OPUS_PACKET_BYTES: usize = 4_000;

// Re-export OpusApplication from types to avoid duplication
pub use crate::types::OpusApplication;

/// Opus codec implementation
pub struct OpusCodec {
    /// Sample rate (8, 12, 16, 24, or 48 kHz)
    sample_rate: u32,
    /// Number of channels (1 or 2)
    channels: u8,
    /// Frame size in samples *per channel* (matches libopus's own
    /// `frame_size` convention). `AudioCodec::encode`/`decode`'s `samples`
    /// buffers are the interleaved total, `frame_size * channels` long.
    frame_size: usize,
    /// Codec configuration
    config: OpusConfig,
    #[cfg(feature = "opus")]
    real: RealBackend,
}

/// The actual libopus encoder/decoder pair, kept behind the `opus` feature
/// so building without it doesn't need libopus at all.
#[cfg(feature = "opus")]
struct RealBackend {
    encoder: opus::Encoder,
    decoder: opus::Decoder,
}

// SAFETY: `opus::Encoder`/`Decoder` wrap a raw libopus state pointer that
// libopus itself only allows exclusive (single-thread-at-a-time) access to
// ("a single codec state may only be accessed from a single thread at a
// time and any required locking must be performed by the caller" - opus
// crate docs). That's fine here: every `OpusCodec`/`RealBackend` method
// that touches `encoder`/`decoder` takes `&mut self` (encode, decode,
// reset, set_bitrate, set_complexity); no `&self` method ever reads these
// fields, so concurrent shared (`&RealBackend`) access can never race on
// the underlying C state. `Sync` is required transitively because
// `AudioCodec: Send + Sync`.
#[cfg(feature = "opus")]
unsafe impl Sync for RealBackend {}

#[cfg(feature = "opus")]
fn to_opus_application(application: OpusApplication) -> opus::Application {
    match application {
        OpusApplication::Voip => opus::Application::Voip,
        OpusApplication::Audio => opus::Application::Audio,
        OpusApplication::RestrictedLowDelay => opus::Application::LowDelay,
    }
}

/// Maps a validated channel count (1 or 2 - `OpusCodec::new` rejects
/// anything else before this is ever called) to the crate's `Channels` enum.
#[cfg(feature = "opus")]
fn to_opus_channels(channels: u8) -> opus::Channels {
    if channels == 1 {
        opus::Channels::Mono
    } else {
        opus::Channels::Stereo
    }
}

#[cfg(feature = "opus")]
fn apply_encoder_config(encoder: &mut opus::Encoder, config: &OpusConfig) -> Result<()> {
    encoder
        .set_bitrate(opus::Bitrate::Bits(config.bitrate as i32))
        .map_err(|e| CodecError::ExternalLibraryError {
            library: "opus".to_string(),
            error: format!("set_bitrate: {e}"),
        })?;
    encoder
        .set_vbr(config.vbr)
        .map_err(|e| CodecError::ExternalLibraryError {
            library: "opus".to_string(),
            error: format!("set_vbr: {e}"),
        })?;
    encoder
        .set_vbr_constraint(config.cvbr)
        .map_err(|e| CodecError::ExternalLibraryError {
            library: "opus".to_string(),
            error: format!("set_vbr_constraint: {e}"),
        })?;
    encoder
        .set_complexity(i32::from(config.complexity))
        .map_err(|e| CodecError::ExternalLibraryError {
            library: "opus".to_string(),
            error: format!("set_complexity: {e}"),
        })?;
    encoder
        .set_inband_fec(config.inband_fec)
        .map_err(|e| CodecError::ExternalLibraryError {
            library: "opus".to_string(),
            error: format!("set_inband_fec: {e}"),
        })?;
    encoder
        .set_packet_loss_perc(i32::from(config.packet_loss_perc))
        .map_err(|e| CodecError::ExternalLibraryError {
            library: "opus".to_string(),
            error: format!("set_packet_loss_perc: {e}"),
        })?;
    encoder
        .set_dtx(config.dtx)
        .map_err(|e| CodecError::ExternalLibraryError {
            library: "opus".to_string(),
            error: format!("set_dtx: {e}"),
        })?;
    Ok(())
}

/// `Opus` codec configuration.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct OpusConfig {
    /// Application type (`VoIP`, audio, or low delay).
    pub application: OpusApplication,
    /// Bitrate in bits per second
    pub bitrate: u32,
    /// Enable variable bitrate
    pub vbr: bool,
    /// Enable constrained VBR
    pub cvbr: bool,
    /// Complexity (0-10)
    pub complexity: u8,
    /// Enable inband FEC
    pub inband_fec: bool,
    /// DTX (Discontinuous Transmission)
    pub dtx: bool,
    /// Packet loss percentage (0-100)
    pub packet_loss_perc: u8,
    /// Force mono encoding
    pub force_mono: bool,
}

impl Default for OpusConfig {
    fn default() -> Self {
        Self {
            application: OpusApplication::Voip,
            bitrate: 64000,
            vbr: true,
            cvbr: false,
            complexity: 5,
            inband_fec: false,
            dtx: false,
            packet_loss_perc: 0,
            force_mono: false,
        }
    }
}

impl OpusCodec {
    /// Create a new `Opus` codec.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported parameters or if libopus cannot create
    /// and configure the encoder and decoder.
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(config: CodecConfig) -> Result<Self> {
        if config.codec_type != crate::types::CodecType::Opus {
            return Err(CodecError::unsupported_codec(format!(
                "{} configuration passed to OpusCodec",
                config.codec_type
            )));
        }
        config.validate()?;
        let sample_rate = config.sample_rate.hz();

        // Opus supports 8, 12, 16, 24, 48 kHz
        if ![8000, 12000, 16000, 24000, 48000].contains(&sample_rate) {
            return Err(CodecError::InvalidSampleRate {
                rate: sample_rate,
                supported: vec![8000, 12000, 16000, 24000, 48000],
            });
        }

        // Opus supports mono and stereo
        if config.channels == 0 || config.channels > 2 {
            return Err(CodecError::InvalidChannelCount {
                channels: config.channels,
                supported: vec![1, 2],
            });
        }

        // Calculate frame size from the configured duration or default 20 ms.
        let frame_duration_ms = config.frame_size_ms.unwrap_or(20.0);
        let frame_size = opus_frame_size(sample_rate, frame_duration_ms).ok_or_else(|| {
            CodecError::invalid_config(format!(
                "Unsupported Opus frame duration: {frame_duration_ms}ms"
            ))
        })?;

        // The codec-specific field was the public Opus configuration surface
        // before the real backend landed, so it remains authoritative. The
        // generic `with_bitrate` convenience setter keeps both values in sync.
        let opus_config = OpusConfig {
            application: config.parameters.opus.application,
            bitrate: config.parameters.opus.bitrate,
            vbr: config.parameters.opus.vbr,
            cvbr: config.parameters.opus.cvbr,
            complexity: config.parameters.opus.complexity,
            inband_fec: config.parameters.opus.inband_fec,
            dtx: config.parameters.opus.dtx,
            packet_loss_perc: config.parameters.opus.packet_loss_perc,
            force_mono: config.parameters.opus.force_mono,
        };

        if opus_config.complexity > 10 {
            return Err(CodecError::invalid_config(
                "Opus complexity must be in the range 0-10",
            ));
        }
        if opus_config.packet_loss_perc > 100 {
            return Err(CodecError::invalid_config(
                "Opus packet loss percentage must be in the range 0-100",
            ));
        }
        if !(6_000..=510_000).contains(&opus_config.bitrate) {
            return Err(CodecError::InvalidBitrate {
                bitrate: opus_config.bitrate,
                min: 6_000,
                max: 510_000,
            });
        }

        debug!(
            "Creating Opus codec: {}Hz, {}ch, {}bps, {:?} mode",
            sample_rate, config.channels, opus_config.bitrate, opus_config.application
        );

        #[cfg(feature = "opus")]
        let real = {
            let opus_channels = to_opus_channels(config.channels);
            let mut encoder = opus::Encoder::new(
                sample_rate,
                opus_channels,
                to_opus_application(opus_config.application),
            )
            .map_err(|e| CodecError::ExternalLibraryError {
                library: "opus".to_string(),
                error: format!("encoder init: {e}"),
            })?;
            apply_encoder_config(&mut encoder, &opus_config)?;

            let decoder = opus::Decoder::new(sample_rate, opus_channels).map_err(|e| {
                CodecError::ExternalLibraryError {
                    library: "opus".to_string(),
                    error: format!("decoder init: {e}"),
                }
            })?;

            RealBackend { encoder, decoder }
        };

        Ok(Self {
            sample_rate,
            channels: config.channels,
            frame_size,
            config: opus_config,
            #[cfg(feature = "opus")]
            real,
        })
    }

    /// Get the compression ratio (variable for `Opus`).
    #[allow(clippy::cast_precision_loss)]
    pub fn compression_ratio(&self) -> f32 {
        let uncompressed_bits = self.frame_size as f32 * 16.0 * f32::from(self.channels);
        let compressed_bits =
            self.config.bitrate as f32 * (self.frame_size as f32 / self.sample_rate as f32);
        compressed_bits / uncompressed_bits
    }

    /// Set the bitrate.
    ///
    /// # Errors
    ///
    /// Returns an error if the bitrate is outside libopus's supported range
    /// or if libopus rejects the update.
    pub fn set_bitrate(&mut self, bitrate: u32) -> Result<()> {
        if !(6_000..=510_000).contains(&bitrate) {
            return Err(CodecError::InvalidBitrate {
                bitrate,
                min: 6_000,
                max: 510_000,
            });
        }

        self.config.bitrate = bitrate;
        #[cfg(feature = "opus")]
        {
            self.real
                .encoder
                .set_bitrate(opus::Bitrate::Bits(bitrate as i32))
                .map_err(|e| CodecError::ExternalLibraryError {
                    library: "opus".to_string(),
                    error: format!("set_bitrate: {e}"),
                })?;
        }
        debug!("Opus bitrate set to {} bps", bitrate);
        Ok(())
    }

    /// Set complexity level (0-10).
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-range value or if libopus rejects the
    /// update.
    pub fn set_complexity(&mut self, complexity: u8) -> Result<()> {
        if complexity > 10 {
            return Err(CodecError::invalid_config("Complexity must be 0-10"));
        }

        self.config.complexity = complexity;
        #[cfg(feature = "opus")]
        {
            self.real
                .encoder
                .set_complexity(i32::from(complexity))
                .map_err(|e| CodecError::ExternalLibraryError {
                    library: "opus".to_string(),
                    error: format!("set_complexity: {e}"),
                })?;
        }
        debug!("Opus complexity set to {}", complexity);
        Ok(())
    }

    /// Validate input samples before encoding.
    fn validate_input(&self, samples: &[i16]) -> Result<()> {
        let channels = usize::from(self.channels);
        if !samples.len().is_multiple_of(channels) {
            return Err(CodecError::invalid_format(format!(
                "Opus input sample count {} is not divisible by {} channels",
                samples.len(),
                self.channels
            )));
        }
        validate_opus_frame(
            &samples[..samples.len() / channels],
            SampleRate::from_hz(self.sample_rate),
        )
    }

    /// Real Opus encoding via libopus.
    #[cfg(feature = "opus")]
    fn real_encode(&mut self, samples: &[i16]) -> Result<Vec<u8>> {
        // 1275 bytes is the largest a single Opus packet can ever be
        // (RFC 6716 section 3.2.1).
        let mut output = vec![0u8; 1275];
        let written = self
            .real
            .encoder
            .encode(samples, &mut output)
            .map_err(|e| CodecError::EncodingFailed {
                reason: e.to_string(),
            })?;
        output.truncate(written);
        Ok(output)
    }

    /// Real Opus decoding via libopus.
    #[cfg(feature = "opus")]
    fn real_decode(&mut self, data: &[u8]) -> Result<Vec<i16>> {
        // A decoder output buffer must accommodate the maximum Opus packet
        // duration (120ms), regardless of the configured encoder frame size.
        let max_samples_per_channel = self.sample_rate as usize * 120 / 1000;
        let mut output = vec![0i16; max_samples_per_channel * usize::from(self.channels)];
        let per_channel_written =
            self.real
                .decoder
                .decode(data, &mut output, false)
                .map_err(|e| CodecError::DecodingFailed {
                    reason: e.to_string(),
                })?;
        output.truncate(per_channel_written * usize::from(self.channels));
        Ok(output)
    }

    /// Deterministic Opus stub (see the module docs for when this runs
    /// instead of [`Self::real_encode`]). Ignores the actual audio content;
    /// output size just tracks the configured bitrate.
    #[cfg(not(feature = "opus"))]
    fn simulate_encode(&mut self, samples: &[i16]) -> Result<Vec<u8>> {
        // Calculate target size based on bitrate
        let frame_duration_ms =
            (samples.len() as f32 * 1000.0) / (self.sample_rate as f32 * self.channels as f32);
        let target_bits = (self.config.bitrate as f32 * frame_duration_ms / 1000.0) as usize;
        let target_bytes = target_bits / 8;

        let mut encoded = Vec::with_capacity(target_bytes.max(10));

        // Simple simulation - just create dummy data
        for i in 0..target_bytes {
            encoded.push((i % 256) as u8);
        }

        Ok(encoded)
    }

    /// Deterministic Opus stub decode; see [`Self::simulate_encode`].
    #[cfg(not(feature = "opus"))]
    fn simulate_decode(&mut self, data: &[u8]) -> Result<Vec<i16>> {
        let mut samples = vec![0i16; self.frame_size * self.channels as usize];

        // Simple simulation - generate noise based on input
        for (i, sample) in samples.iter_mut().enumerate() {
            let data_idx = i % data.len();
            *sample = ((data[data_idx] as i16) << 8) | (i as i16 & 0xFF);
        }

        Ok(samples)
    }

    /// Encode via whichever backend is compiled in: real libopus when the
    /// `opus` feature is enabled, the deterministic stub otherwise.
    fn backend_encode(&mut self, samples: &[i16]) -> Result<Vec<u8>> {
        #[cfg(feature = "opus")]
        {
            self.real_encode(samples)
        }
        #[cfg(not(feature = "opus"))]
        {
            self.simulate_encode(samples)
        }
    }

    /// Decode via whichever backend is compiled in; see
    /// [`Self::backend_encode`].
    fn backend_decode(&mut self, data: &[u8]) -> Result<Vec<i16>> {
        #[cfg(feature = "opus")]
        {
            self.real_decode(data)
        }
        #[cfg(not(feature = "opus"))]
        {
            self.simulate_decode(data)
        }
    }
}

/// Compute the frame size in samples per channel for a given rate and duration.
fn opus_frame_size(sample_rate: u32, frame_duration_ms: f32) -> Option<usize> {
    let divisor = match frame_duration_ms {
        2.5 => 400,
        5.0 => 200,
        10.0 => 100,
        20.0 => 50,
        40.0 => 25,
        60.0 => return usize::try_from(sample_rate.checked_mul(3)? / 50).ok(),
        _ => return None,
    };
    usize::try_from(sample_rate / divisor).ok()
}

impl AudioCodec for OpusCodec {
    fn encode(&mut self, samples: &[i16]) -> Result<Vec<u8>> {
        self.validate_input(samples)?;

        let encoded = self.backend_encode(samples)?;

        trace!(
            "Opus encoded {} samples to {} bytes",
            samples.len(),
            encoded.len()
        );

        Ok(encoded)
    }

    fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>> {
        if data.is_empty() {
            return Err(CodecError::InvalidPayload {
                details: "Empty encoded data".to_string(),
            });
        }

        let decoded = self.backend_decode(data)?;

        trace!(
            "Opus decoded {} bytes to {} samples",
            data.len(),
            decoded.len()
        );

        Ok(decoded)
    }

    fn info(&self) -> CodecInfo {
        CodecInfo {
            name: "Opus",
            sample_rate: self.sample_rate,
            channels: self.channels,
            bitrate: self.config.bitrate,
            frame_size: self.frame_size,
            payload_type: None, // Opus payload types are negotiated dynamically
        }
    }

    fn reset(&mut self) -> Result<()> {
        // The encoder/decoder carry ADPCM-like prediction state (SILK/CELT
        // history, VBR smoothing) across frames; a fresh instance is the
        // only way to actually clear it. Re-applying the tunable fields
        // mirrors what `new()` does from `self.config`.
        #[cfg(feature = "opus")]
        {
            let opus_channels = to_opus_channels(self.channels);
            let mut encoder = opus::Encoder::new(
                self.sample_rate,
                opus_channels,
                to_opus_application(self.config.application),
            )
            .map_err(|e| CodecError::ResetFailed {
                reason: format!("encoder re-init: {e}"),
            })?;
            apply_encoder_config(&mut encoder, &self.config).map_err(|e| {
                CodecError::ResetFailed {
                    reason: format!("encoder reconfigure: {e}"),
                }
            })?;

            let decoder = opus::Decoder::new(self.sample_rate, opus_channels).map_err(|e| {
                CodecError::ResetFailed {
                    reason: format!("decoder re-init: {e}"),
                }
            })?;

            self.real = RealBackend { encoder, decoder };
        }
        debug!("Opus codec reset");
        Ok(())
    }

    fn frame_size(&self) -> usize {
        self.frame_size
    }

    fn supports_variable_frame_size(&self) -> bool {
        true // Opus supports multiple frame sizes
    }
}

impl AudioCodecExt for OpusCodec {
    fn encode_to_buffer(&mut self, samples: &[i16], output: &mut [u8]) -> Result<usize> {
        self.validate_input(samples)?;

        let encoded = self.backend_encode(samples)?;

        if output.len() < encoded.len() {
            return Err(CodecError::BufferTooSmall {
                needed: encoded.len(),
                actual: output.len(),
            });
        }

        output[..encoded.len()].copy_from_slice(&encoded);

        trace!(
            "Opus encoded {} samples to {} bytes (zero-alloc)",
            samples.len(),
            encoded.len()
        );

        Ok(encoded.len())
    }

    fn decode_to_buffer(&mut self, data: &[u8], output: &mut [i16]) -> Result<usize> {
        if data.is_empty() {
            return Err(CodecError::InvalidPayload {
                details: "Empty encoded data".to_string(),
            });
        }

        let decoded = self.backend_decode(data)?;

        if output.len() < decoded.len() {
            return Err(CodecError::BufferTooSmall {
                needed: decoded.len(),
                actual: output.len(),
            });
        }

        output[..decoded.len()].copy_from_slice(&decoded);

        trace!(
            "Opus decoded {} bytes to {} samples (zero-alloc)",
            data.len(),
            decoded.len()
        );

        Ok(decoded.len())
    }

    fn max_encoded_size(&self, _input_samples: usize) -> usize {
        MAX_OPUS_PACKET_BYTES
    }

    fn max_decoded_size(&self, _input_bytes: usize) -> usize {
        self.sample_rate as usize * 120 / 1000 * usize::from(self.channels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CodecConfig, CodecType, SampleRate};

    fn create_test_config() -> CodecConfig {
        CodecConfig::new(CodecType::Opus)
            .with_sample_rate(SampleRate::Rate48000)
            .with_channels(1)
            .with_frame_size_ms(20.0)
    }

    #[test]
    fn test_opus_creation() {
        let config = create_test_config();
        let codec = OpusCodec::new(config);
        assert!(codec.is_ok());

        let codec = codec.unwrap();
        assert_eq!(codec.frame_size(), 960); // 20ms at 48kHz

        let info = codec.info();
        assert_eq!(info.name, "Opus");
        assert_eq!(info.sample_rate, 48000);
        assert_eq!(info.payload_type, None);
    }

    #[test]
    fn test_encoding_decoding_roundtrip() {
        let config = create_test_config();
        let mut codec = OpusCodec::new(config).unwrap();

        // Create a deterministic square-wave test signal without lossy casts.
        let samples: Vec<i16> = (0..960)
            .map(|index| {
                if (index / 24) % 2 == 0 {
                    16_000
                } else {
                    -16_000
                }
            })
            .collect();

        // Encode
        let encoded = codec.encode(&samples).unwrap();
        assert!(!encoded.is_empty());

        // Decode
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), samples.len());
    }

    #[test]
    fn test_real_backend_output_depends_on_pcm_input() {
        let silence = vec![0; 960];
        let tone: Vec<i16> = (0..960)
            .map(|index| {
                if (index / 55) % 2 == 0 {
                    12_000
                } else {
                    -12_000
                }
            })
            .collect();

        // Use independent encoders so codec history cannot explain a packet
        // difference. The retired simulator ignored PCM input and emitted the
        // same counter bytes for both frames.
        let silence_packet = OpusCodec::new(create_test_config())
            .unwrap()
            .encode(&silence)
            .unwrap();
        let tone_packet = OpusCodec::new(create_test_config())
            .unwrap()
            .encode(&tone)
            .unwrap();

        assert_ne!(silence_packet, tone_packet);
        assert_eq!(
            opus::packet::get_nb_samples(&tone_packet, 48_000).unwrap(),
            960
        );
    }

    #[cfg(feature = "opus")]
    #[test]
    fn test_opus_sim_with_real_backend_produces_valid_packets() {
        let mut codec = OpusCodec::new(create_test_config()).unwrap();
        let packet = codec.encode(&[0; 960]).unwrap();

        assert_eq!(opus::packet::get_nb_samples(&packet, 48_000).unwrap(), 960);
        assert_eq!(codec.decode(&packet).unwrap().len(), 960);
    }

    #[test]
    fn test_opus_bitrate_configuration_remains_backward_compatible() {
        let mut specific_config = create_test_config();
        assert_eq!(specific_config.bitrate, Some(64_000));
        specific_config.parameters.opus.bitrate = 32_000;
        let specific_codec = OpusCodec::new(specific_config).unwrap();
        assert_eq!(specific_codec.info().bitrate, 32_000);

        let generic_config = create_test_config().with_bitrate(48_000);
        assert_eq!(generic_config.bitrate, Some(48_000));
        assert_eq!(generic_config.parameters.opus.bitrate, 48_000);
        let generic_codec = OpusCodec::new(generic_config).unwrap();
        assert_eq!(generic_codec.info().bitrate, 48_000);
    }

    #[test]
    fn test_non_opus_configuration_is_rejected() {
        assert!(matches!(
            OpusCodec::new(CodecConfig::g711_pcmu()),
            Err(CodecError::UnsupportedCodec { .. })
        ));
    }

    #[test]
    fn test_invalid_frames_are_rejected() {
        let mut codec = OpusCodec::new(create_test_config()).unwrap();
        assert!(matches!(
            codec.encode(&[0; 123]),
            Err(CodecError::InvalidFrameSize { .. })
        ));
        assert!(matches!(
            codec.decode(&[]),
            Err(CodecError::InvalidPayload { .. })
        ));
        assert!(matches!(
            codec.decode(&[0x03]),
            Err(CodecError::DecodingFailed { .. })
        ));

        let invalid_duration = create_test_config().with_frame_size_ms(7.0);
        assert!(matches!(
            OpusCodec::new(invalid_duration),
            Err(CodecError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn test_stereo_and_variable_duration_buffer_contracts() {
        let stereo_20ms_config = create_test_config().with_channels(2);
        let mut stereo_encoder = OpusCodec::new(stereo_20ms_config.clone()).unwrap();
        assert!(matches!(
            stereo_encoder.encode(&[0; 1_919]),
            Err(CodecError::InvalidFormat { .. })
        ));

        let stereo_frame = vec![1_000; 1_920];
        let mut tiny_encoded = [0; 1];
        let tiny_result = stereo_encoder.encode_to_buffer(&stereo_frame, &mut tiny_encoded);
        assert!(
            matches!(
                tiny_result,
                Err(CodecError::BufferTooSmall {
                    needed: _,
                    actual: 1
                })
            ),
            "unexpected tiny-buffer result: {tiny_result:?}"
        );

        let mut long_encoder = OpusCodec::new(
            create_test_config()
                .with_channels(2)
                .with_frame_size_ms(60.0),
        )
        .unwrap();
        let long_stereo_frame: Vec<i16> = (0..2_880)
            .flat_map(|index| {
                let sample = if (index / 27) % 2 == 0 {
                    10_000
                } else {
                    -10_000
                };
                [sample, -sample]
            })
            .collect();
        let long_packet = long_encoder.encode(&long_stereo_frame).unwrap();

        // A decoder configured for 20 ms must still size the output from the
        // packet on the wire, which may legally contain a longer duration.
        let mut decoder = OpusCodec::new(stereo_20ms_config).unwrap();
        let mut configured_size_only = vec![0; 1_920];
        assert!(matches!(
            decoder.decode_to_buffer(&long_packet, &mut configured_size_only),
            Err(CodecError::BufferTooSmall {
                needed: 5_760,
                actual: 1_920
            })
        ));

        let mut full_output = vec![0; decoder.max_decoded_size(long_packet.len())];
        assert_eq!(
            decoder
                .decode_to_buffer(&long_packet, &mut full_output)
                .unwrap(),
            5_760
        );
    }

    #[test]
    fn max_bitrate_sixty_ms_encode_uses_the_libopus_packet_contract() {
        let config = create_test_config()
            .with_channels(2)
            .with_frame_size_ms(60.0)
            .with_bitrate(510_000);
        let mut codec = OpusCodec::new(config).unwrap();
        let samples: Vec<i16> = (0_usize..2_880)
            .flat_map(|index| {
                let value = u16::try_from(index.wrapping_mul(7_919) % 65_535).unwrap();
                let left = i16::try_from(i32::from(value) - 32_767).unwrap();
                [left, left.wrapping_neg()]
            })
            .collect();
        let encoded = codec.encode(&samples).unwrap();
        assert!(!encoded.is_empty());
        assert!(encoded.len() <= MAX_OPUS_PACKET_BYTES);
        assert_eq!(codec.max_encoded_size(samples.len()), MAX_OPUS_PACKET_BYTES);
    }

    #[test]
    fn test_bitrate_control() {
        let config = create_test_config();
        let mut codec = OpusCodec::new(config).unwrap();

        // Test valid bitrates
        assert!(codec.set_bitrate(32_000).is_ok());
        assert!(codec.set_bitrate(128_000).is_ok());

        // Test invalid bitrates
        assert!(codec.set_bitrate(1_000).is_err());
        assert!(codec.set_bitrate(1_000_000).is_err());
    }

    #[test]
    fn test_complexity_control() {
        let config = create_test_config();
        let mut codec = OpusCodec::new(config).unwrap();

        // Test valid complexity levels
        for complexity in 0..=10 {
            assert!(codec.set_complexity(complexity).is_ok());
        }

        // Test invalid complexity
        assert!(codec.set_complexity(11).is_err());
    }

    // These specifically exercise the real libopus backend. Opus's SILK
    // layer is adaptive/predictive, not a fixed-delay linear filter like
    // G.722's QMF, so a naive "find the best constant sample lag, then
    // measure SNR" approach (which worked well for G.722) doesn't converge
    // to a stable answer here. Energy/RMS-based checks are lag-independent
    // and, as a bonus, are exactly the kind of check that would have
    // caught the old simulate_encode/simulate_decode stub: its output
    // depended only on configured bitrate, not actual sample content, so
    // loud and near-silent input produced equally noisy "decoded" output.
    #[cfg(feature = "opus")]
    mod real_backend {
        use super::*;

        fn tone_at(
            len: usize,
            sample_rate: u32,
            frequency: f32,
            amplitude: f32,
            start: usize,
        ) -> Vec<i16> {
            (0..len)
                .map(|i| {
                    let t = (start + i) as f32 / sample_rate as f32;
                    (amplitude * (2.0 * std::f32::consts::PI * frequency * t).sin()) as i16
                })
                .collect()
        }

        fn tone(len: usize, sample_rate: u32, frequency: f32, amplitude: f32) -> Vec<i16> {
            tone_at(len, sample_rate, frequency, amplitude, 0)
        }

        fn rms(samples: &[i16]) -> f64 {
            let sum_sq: f64 = samples.iter().map(|&s| f64::from(s).powi(2)).sum();
            (sum_sq / samples.len() as f64).sqrt()
        }

        #[test]
        fn silence_roundtrips_to_near_silence() {
            let mut codec = OpusCodec::new(create_test_config()).unwrap();
            let silence = vec![0i16; 960];

            let encoded = codec.encode(&silence).unwrap();
            let decoded = codec.decode(&encoded).unwrap();

            assert_eq!(decoded.len(), silence.len());
            let level = rms(&decoded);
            assert!(
                level < 500.0,
                "silence should decode to near-silence, got RMS {level:.1} (i16 range is +/-32768)"
            );
        }

        #[test]
        fn decoded_energy_tracks_input_energy() {
            let loud = tone(960, 48000, 440.0, 12000.0);
            let quiet = tone(960, 48000, 440.0, 300.0);

            let mut loud_codec = OpusCodec::new(create_test_config()).unwrap();
            let loud_encoded = loud_codec.encode(&loud).unwrap();
            let loud_decoded = loud_codec.decode(&loud_encoded).unwrap();

            let mut quiet_codec = OpusCodec::new(create_test_config()).unwrap();
            let quiet_encoded = quiet_codec.encode(&quiet).unwrap();
            let quiet_decoded = quiet_codec.decode(&quiet_encoded).unwrap();

            let (loud_rms, quiet_rms) = (rms(&loud_decoded), rms(&quiet_decoded));
            assert!(
                loud_rms > quiet_rms * 3.0,
                "a ~40x louder input should decode noticeably louder: loud_rms={loud_rms:.1} quiet_rms={quiet_rms:.1}"
            );
        }

        #[test]
        fn encode_produces_a_valid_opus_packet_size() {
            let mut codec = OpusCodec::new(create_test_config()).unwrap();
            let samples = tone(960, 48000, 440.0, 8000.0);

            let encoded = codec.encode(&samples).unwrap();

            assert!(!encoded.is_empty());
            assert!(
                encoded.len() <= 1275,
                "RFC 6716 section 3.2.1: an Opus packet is never larger than 1275 bytes, got {}",
                encoded.len()
            );
        }

        #[test]
        fn streaming_many_frames_round_trips_without_error() {
            let mut encoder = OpusCodec::new(create_test_config()).unwrap();
            let mut decoder = OpusCodec::new(create_test_config()).unwrap();

            for frame_idx in 0..50usize {
                let samples = tone_at(960, 48000, 440.0, 8000.0, frame_idx * 960);
                let encoded = encoder.encode(&samples).unwrap();
                let decoded = decoder.decode(&encoded).unwrap();
                assert_eq!(decoded.len(), samples.len());
            }
        }

        #[test]
        fn reset_succeeds_and_codec_keeps_working_afterward() {
            let mut codec = OpusCodec::new(create_test_config()).unwrap();
            let samples = tone(960, 48000, 440.0, 8000.0);
            let _ = codec.encode(&samples).unwrap();

            codec.reset().unwrap();

            let encoded = codec.encode(&samples).unwrap();
            let decoded = codec.decode(&encoded).unwrap();
            assert_eq!(decoded.len(), samples.len());
        }

        #[test]
        fn set_bitrate_and_complexity_propagate_to_the_real_encoder() {
            let mut codec = OpusCodec::new(create_test_config()).unwrap();
            codec.set_bitrate(96_000).unwrap();
            codec.set_complexity(3).unwrap();

            assert_eq!(
                codec.real.encoder.get_bitrate().unwrap(),
                opus::Bitrate::Bits(96_000)
            );
            assert_eq!(codec.real.encoder.get_complexity().unwrap(), 3);
        }
    }
}
