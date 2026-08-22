//! SDES Server Implementation
//!
//! This module provides SDES (Security DEScriptions) server functionality for the API layer.
//! It handles crypto offer generation, answer processing, and key confirmation.

use async_trait::async_trait;
use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::api::common::config::{SecurityConfig, SecurityInfo, SecurityMode, SrtpProfile};
use crate::api::common::error::SecurityError;
use crate::api::server::security::{
    ClientSecurityContext, ServerSecurityConfig, ServerSecurityContext, SocketHandle,
};
use crate::security::sdes::{SdesCryptoAttribute, SdesNegotiator};
use crate::srtp::{SrtpContext, SrtpCryptoSuite, SRTP_AES128_CM_SHA1_32, SRTP_AES128_CM_SHA1_80};

/// RFC 4568 §6.2 wire name for the suites this module offers.
fn suite_wire_name(suite: &SrtpCryptoSuite) -> Result<&'static str, SecurityError> {
    match (suite.key_length, suite.tag_length) {
        (16, 10) => Ok("AES_CM_128_HMAC_SHA1_80"),
        (16, 4) => Ok("AES_CM_128_HMAC_SHA1_32"),
        _ => Err(SecurityError::Configuration(format!(
            "unsupported crypto suite for SDES: {suite:?}"
        ))),
    }
}

fn suite_from_wire_name(name: &str) -> Result<SrtpCryptoSuite, SecurityError> {
    match name {
        "AES_CM_128_HMAC_SHA1_80" => Ok(SRTP_AES128_CM_SHA1_80),
        "AES_CM_128_HMAC_SHA1_32" => Ok(SRTP_AES128_CM_SHA1_32),
        other => Err(SecurityError::Configuration(format!(
            "unsupported crypto suite: {other}"
        ))),
    }
}

/// Format an `SdesCryptoAttribute` as a bare `a=crypto:` line body. This
/// module's `Vec<String>` SDP lines are only ever consumed by this same
/// module — no real SDP text is produced here, unlike the actual SIP
/// adapter's typed `sip-core` integration.
fn format_crypto_line(attr: &SdesCryptoAttribute) -> Result<String, SecurityError> {
    Ok(format!(
        "{} {} inline:{}",
        attr.tag,
        suite_wire_name(&attr.suite)?,
        attr.key_inline
    ))
}

/// Parse a bare `a=crypto:` line body (as produced by
/// [`format_crypto_line`]) back into an `SdesCryptoAttribute`.
fn parse_crypto_line(line: &str) -> Result<SdesCryptoAttribute, SecurityError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(SecurityError::Configuration(
            "invalid SDES crypto attribute format".to_string(),
        ));
    }
    let tag: u32 = parts[0]
        .parse()
        .map_err(|_| SecurityError::Configuration("invalid tag in crypto attribute".to_string()))?;
    let suite = suite_from_wire_name(parts[1])?;
    let key_inline = parts[2]
        .strip_prefix("inline:")
        .ok_or_else(|| SecurityError::Configuration("missing inline: key".to_string()))?
        .to_string();
    Ok(SdesCryptoAttribute::new(tag, suite, key_inline))
}

/// SDES server configuration
#[derive(Debug, Clone)]
pub struct SdesServerConfig {
    /// Supported SRTP profiles in order of preference
    pub supported_profiles: Vec<SrtpProfile>,
    /// Number of crypto attributes to include in offers
    pub offer_count: usize,
    /// Whether to require strong crypto suites only
    pub require_strong_crypto: bool,
    /// Maximum number of concurrent key exchanges
    pub max_concurrent_exchanges: usize,
}

impl Default for SdesServerConfig {
    fn default() -> Self {
        Self {
            supported_profiles: vec![
                SrtpProfile::AesCm128HmacSha1_80,
                SrtpProfile::AesCm128HmacSha1_32,
            ],
            offer_count: 2,
            require_strong_crypto: true,
            max_concurrent_exchanges: 100,
        }
    }
}

/// SDES server state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdesServerState {
    /// Initial state
    Initial,
    /// Offer generated and sent
    OfferGenerated,
    /// Processing answer
    ProcessingAnswer,
    /// Key exchange completed
    Completed,
    /// Error state
    Failed,
}

/// SDES server session for handling per-client crypto negotiation
#[allow(dead_code)] // retained (liveness/Drop hold or reserved); not read
pub struct SdesServerSession {
    /// Session identifier
    pub session_id: String,
    /// Configuration
    #[allow(dead_code)] // retained (liveness/Drop hold or reserved); not read
    config: SdesServerConfig,
    /// Current state
    state: Arc<RwLock<SdesServerState>>,
    /// Offerer-role negotiator, holding our locally-generated keys per
    /// offered tag until the answer arrives. `None` before
    /// `generate_offer` and after the exchange completes (its per-tag
    /// state is consumed by [`SdesNegotiator::accept_answer`]).
    negotiator: Arc<RwLock<Option<SdesNegotiator>>>,
    /// Established SRTP context (if any)
    srtp_context: Arc<RwLock<Option<SrtpContext>>>,
    /// Generated crypto attributes
    generated_crypto: Arc<RwLock<Vec<SdesCryptoAttribute>>>,
    /// Selected crypto attribute
    selected_crypto: Arc<RwLock<Option<SdesCryptoAttribute>>>,
}

impl SdesServerSession {
    /// Create a new SDES server session
    pub fn new(session_id: String, config: SdesServerConfig) -> Self {
        Self {
            session_id,
            config,
            state: Arc::new(RwLock::new(SdesServerState::Initial)),
            negotiator: Arc::new(RwLock::new(None)),
            srtp_context: Arc::new(RwLock::new(None)),
            generated_crypto: Arc::new(RwLock::new(Vec::new())),
            selected_crypto: Arc::new(RwLock::new(None)),
        }
    }

    /// Create SDES server session from security config
    pub fn from_security_config(
        session_id: String,
        config: &SecurityConfig,
    ) -> Result<Self, SecurityError> {
        let server_config = SdesServerConfig {
            supported_profiles: config.srtp_profiles.clone(),
            offer_count: config.srtp_profiles.len().min(4),
            require_strong_crypto: config.required,
            max_concurrent_exchanges: 100,
        };
        Ok(Self::new(session_id, server_config))
    }

    /// Get current state
    pub async fn get_state(&self) -> SdesServerState {
        *self.state.read().await
    }

    /// Check if key exchange is complete
    pub async fn is_completed(&self) -> bool {
        *self.state.read().await == SdesServerState::Completed
    }

    /// Generate SDP offer with crypto attributes
    /// Returns SDP lines with crypto attributes for inclusion in SDP offer
    pub async fn generate_offer(&self) -> Result<Vec<String>, SecurityError> {
        let mut state = self.state.write().await;
        if *state != SdesServerState::Initial {
            return Err(SecurityError::InvalidState(
                "SDES server session not in initial state".to_string(),
            ));
        }

        *state = SdesServerState::OfferGenerated;
        drop(state);

        info!(
            "SDES server session {}: Generating crypto offer",
            self.session_id
        );

        let suites = crate::api::common::config::implemented_srtp_suites(
            &self.config.supported_profiles,
        )?;
        let (offerer, attrs) = match SdesNegotiator::new_offerer(&suites) {
            Ok(result) => result,
            Err(e) => {
                *self.state.write().await = SdesServerState::Failed;
                return Err(SecurityError::CryptoError(format!(
                    "SDES offer generation failed: {e}"
                )));
            }
        };

        let offer_lines: Result<Vec<String>, SecurityError> = attrs
            .iter()
            .map(|attr| format_crypto_line(attr).map(|line| format!("a=crypto:{line}")))
            .collect();
        let offer_lines = match offer_lines {
            Ok(lines) => lines,
            Err(e) => {
                *self.state.write().await = SdesServerState::Failed;
                return Err(e);
            }
        };

        *self.negotiator.write().await = Some(offerer);
        *self.generated_crypto.write().await = attrs;

        info!(
            "SDES server session {}: Generated {} crypto attributes",
            self.session_id,
            offer_lines.len()
        );
        for (i, line) in offer_lines.iter().enumerate() {
            debug!("  Crypto {}: {}", i + 1, line);
        }

        Ok(offer_lines)
    }

    /// Process SDP answer containing selected crypto attribute
    /// Returns true if key exchange is now complete
    pub async fn process_answer(&self, sdp_answer: &[String]) -> Result<bool, SecurityError> {
        let mut state = self.state.write().await;
        if *state != SdesServerState::OfferGenerated {
            return Err(SecurityError::InvalidState(
                "SDES server session not in offer-generated state".to_string(),
            ));
        }

        *state = SdesServerState::ProcessingAnswer;
        drop(state);

        info!(
            "SDES server session {}: Processing SDP answer with {} lines",
            self.session_id,
            sdp_answer.len()
        );

        // Extract crypto lines from SDP answer
        let crypto_lines: Vec<String> = sdp_answer
            .iter()
            .filter(|line| line.trim().starts_with("a=crypto:"))
            .cloned()
            .collect();

        if crypto_lines.is_empty() {
            *self.state.write().await = SdesServerState::Failed;
            return Err(SecurityError::Configuration(
                "No crypto attributes found in SDP answer".to_string(),
            ));
        }

        if crypto_lines.len() > 1 {
            warn!(
                "SDP answer contains {} crypto attributes, expected 1",
                crypto_lines.len()
            );
        }

        info!("Found {} crypto attributes in answer", crypto_lines.len());
        for (i, line) in crypto_lines.iter().enumerate() {
            debug!("  Crypto {}: {}", i + 1, line);
        }

        let answer_attr = match crypto_lines
            .first()
            .and_then(|line| line.strip_prefix("a=crypto:"))
            .map(parse_crypto_line)
        {
            Some(Ok(attr)) => attr,
            Some(Err(e)) => {
                *self.state.write().await = SdesServerState::Failed;
                return Err(e);
            }
            None => {
                *self.state.write().await = SdesServerState::Failed;
                return Err(SecurityError::Configuration(
                    "malformed a=crypto line in answer".to_string(),
                ));
            }
        };

        let negotiator = self.negotiator.write().await.take();
        let Some(negotiator) = negotiator else {
            *self.state.write().await = SdesServerState::Failed;
            return Err(SecurityError::InvalidState(
                "process_answer called before generate_offer".to_string(),
            ));
        };

        match negotiator.accept_answer(&answer_attr) {
            Ok(pair) => {
                *self.srtp_context.write().await = Some(pair.send_ctx);
                info!(
                    "SDES server session {}: SRTP context established",
                    self.session_id
                );

                *self.selected_crypto.write().await = Some(answer_attr);

                *self.state.write().await = SdesServerState::Completed;
                info!(
                    "SDES server session {}: Key exchange completed successfully",
                    self.session_id
                );

                Ok(true)
            }
            Err(e) => {
                error!("SDES answer processing failed: {}", e);
                *self.state.write().await = SdesServerState::Failed;
                Err(SecurityError::CryptoError(format!(
                    "SDES answer processing failed: {}",
                    e
                )))
            }
        }
    }

    /// Get selected crypto attribute info for logging/debugging
    pub async fn get_selected_crypto_info(&self) -> Option<String> {
        self.selected_crypto
            .read()
            .await
            .as_ref()
            .map(|attr| format!("tag={}, suite={:?}", attr.tag, attr.suite))
    }

    /// Get generated crypto attributes (for logging/debugging)
    pub async fn get_generated_crypto_info(&self) -> Vec<String> {
        self.generated_crypto
            .read()
            .await
            .iter()
            .map(|attr| format!("tag={}, suite={:?}", attr.tag, attr.suite))
            .collect()
    }

    /// Get session ID
    pub fn get_session_id(&self) -> &str {
        &self.session_id
    }
}

/// SDES server for managing multiple client sessions
pub struct SdesServer {
    /// Configuration
    config: SdesServerConfig,
    /// Active sessions by session ID
    sessions: Arc<RwLock<std::collections::HashMap<String, Arc<SdesServerSession>>>>,
}

impl SdesServer {
    /// Create a new SDES server
    pub fn new(config: SdesServerConfig) -> Result<Self, SecurityError> {
        crate::api::common::config::implemented_srtp_suites(&config.supported_profiles)?;
        Ok(Self {
            config,
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
        })
    }

    /// Create SDES server from security config
    pub fn from_security_config(config: &SecurityConfig) -> Result<Self, SecurityError> {
        let server_config = SdesServerConfig {
            supported_profiles: config.srtp_profiles.clone(),
            offer_count: config.srtp_profiles.len().min(4),
            require_strong_crypto: config.required,
            max_concurrent_exchanges: 100,
        };
        Self::new(server_config)
    }

    /// Create a new session for a client
    pub async fn create_session(
        &self,
        session_id: String,
    ) -> Result<Arc<SdesServerSession>, SecurityError> {
        let mut sessions = self.sessions.write().await;

        if sessions.len() >= self.config.max_concurrent_exchanges {
            return Err(SecurityError::Configuration(
                "Maximum concurrent SDES exchanges reached".to_string(),
            ));
        }

        if sessions.contains_key(&session_id) {
            return Err(SecurityError::Configuration(format!(
                "Session {} already exists",
                session_id
            )));
        }

        let session = Arc::new(SdesServerSession::new(
            session_id.clone(),
            self.config.clone(),
        ));
        sessions.insert(session_id.clone(), session.clone());

        info!(
            "SDES server: Created session {} (total sessions: {})",
            session_id,
            sessions.len()
        );

        Ok(session)
    }

    /// Get an existing session
    pub async fn get_session(&self, session_id: &str) -> Option<Arc<SdesServerSession>> {
        self.sessions.read().await.get(session_id).cloned()
    }

    /// Remove a session
    pub async fn remove_session(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.write().await;
        let removed = sessions.remove(session_id).is_some();

        if removed {
            info!(
                "SDES server: Removed session {} (total sessions: {})",
                session_id,
                sessions.len()
            );
        }

        removed
    }

    /// Get number of active sessions
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Get all session IDs
    pub async fn get_session_ids(&self) -> Vec<String> {
        self.sessions.read().await.keys().cloned().collect()
    }
}

/// Configuration-only companion for a pre-shared-key SRTP server.
///
/// This type validates and describes key material but does not own or install
/// the [`crate::srtp::SrtpContext`] that protects media. The default media
/// transport installs that crypto context separately; a standalone instance
/// therefore reports [`ServerSecurityContext::is_secure`] as `false`.
#[allow(dead_code)] // retained (liveness/Drop hold or reserved); not read
pub struct SrtpServerSecurityContext {
    /// Configuration
    config: ServerSecurityConfig,
    /// Names derived only after the complete profile list validates.
    advertised_profiles: Vec<String>,
    /// SDES server for key management
    #[allow(dead_code)] // retained (liveness/Drop hold or reserved); not read
    sdes_server: Arc<SdesServer>,
    /// Socket handle
    socket: Arc<RwLock<Option<SocketHandle>>>,
    /// Client contexts (SRTP doesn't need per-client handshakes)
    client_contexts: Arc<RwLock<Vec<Arc<dyn ClientSecurityContext + Send + Sync>>>>,
}

impl SrtpServerSecurityContext {
    /// Create a new SRTP-only server security context
    pub async fn new(config: ServerSecurityConfig) -> Result<Arc<Self>, SecurityError> {
        config.validate()?;

        let advertised_profiles =
            crate::api::common::config::implemented_srtp_profile_names(&config.srtp_profiles)?;

        // Create SDES server config from security config
        let sdes_config = SdesServerConfig {
            supported_profiles: config.srtp_profiles.clone(),
            offer_count: config.srtp_profiles.len().min(4),
            require_strong_crypto: true,
            max_concurrent_exchanges: 100,
        };

        let sdes_server = Arc::new(SdesServer::new(sdes_config)?);

        let ctx = Self {
            config,
            advertised_profiles,
            sdes_server,
            socket: Arc::new(RwLock::new(None)),
            client_contexts: Arc::new(RwLock::new(Vec::new())),
        };

        info!("Created SRTP-only server security context (pre-shared keys)");
        Ok(Arc::new(ctx))
    }
}

#[async_trait]
impl ServerSecurityContext for SrtpServerSecurityContext {
    async fn initialize(&self) -> Result<(), SecurityError> {
        debug!("Initializing SRTP-only server security context");
        // No DTLS initialization needed for pre-shared keys
        Ok(())
    }

    async fn set_socket(&self, socket: SocketHandle) -> Result<(), SecurityError> {
        let mut socket_lock = self.socket.write().await;
        *socket_lock = Some(socket);
        debug!("SRTP-only server: Set socket handle");
        Ok(())
    }

    async fn get_fingerprint(&self) -> Result<String, SecurityError> {
        Err(SecurityError::Configuration(
            "Fingerprints not used with pre-shared key SRTP".to_string(),
        ))
    }

    async fn get_fingerprint_algorithm(&self) -> Result<String, SecurityError> {
        Err(SecurityError::Configuration(
            "Fingerprint algorithm not used with pre-shared key SRTP".to_string(),
        ))
    }

    async fn start_listening(&self) -> Result<(), SecurityError> {
        debug!(
            "SRTP-only server: Start listening (no special listening needed for pre-shared keys)"
        );
        Ok(())
    }

    async fn stop_listening(&self) -> Result<(), SecurityError> {
        debug!("SRTP-only server: Stop listening");
        Ok(())
    }

    async fn start_packet_handler(&self) -> Result<(), SecurityError> {
        debug!("SRTP-only server: No packet handler needed for pre-shared keys");
        Ok(())
    }

    async fn capture_initial_packet(&self) -> Result<Option<(Vec<u8>, SocketAddr)>, SecurityError> {
        debug!("SRTP-only server: No initial packet capture needed for pre-shared keys");
        Ok(None)
    }

    async fn create_client_context(
        &self,
        addr: SocketAddr,
    ) -> Result<Arc<dyn ClientSecurityContext + Send + Sync>, SecurityError> {
        debug!("SRTP-only server: Creating client context for {}", addr);

        // Create a simple SRTP client context that just holds the address
        let client_ctx = Arc::new(SrtpServerClientContext::new(addr, self.config.clone()).await?)
            as Arc<dyn ClientSecurityContext + Send + Sync>;

        // Add to our list
        let mut clients = self.client_contexts.write().await;
        clients.push(client_ctx.clone());

        Ok(client_ctx)
    }

    async fn get_client_contexts(&self) -> Vec<Arc<dyn ClientSecurityContext + Send + Sync>> {
        self.client_contexts.read().await.clone()
    }

    async fn remove_client(&self, addr: SocketAddr) -> Result<(), SecurityError> {
        let mut clients = self.client_contexts.write().await;
        clients.retain(|_ctx| {
            // This is a bit hacky - in a real implementation you'd have a better way to identify clients
            true // For now, we don't remove them
        });
        debug!("SRTP-only server: Removed client {}", addr);
        Ok(())
    }

    async fn on_client_secure(
        &self,
        _callback: Box<dyn Fn(Arc<dyn ClientSecurityContext + Send + Sync>) + Send + Sync>,
    ) -> Result<(), SecurityError> {
        debug!("SRTP-only server: Client secure callback registered (but not needed for pre-shared keys)");
        Ok(())
    }

    async fn get_supported_srtp_profiles(&self) -> Vec<SrtpProfile> {
        self.config.srtp_profiles.clone()
    }

    fn is_secure(&self) -> bool {
        false
    }

    fn get_security_info(&self) -> SecurityInfo {
        let crypto_suites = self.advertised_profiles.clone();
        let srtp_profile = crypto_suites.first().cloned();

        SecurityInfo {
            mode: SecurityMode::Srtp,
            fingerprint: None, // No fingerprint for pre-shared keys
            fingerprint_algorithm: None,
            crypto_suites,
            key_params: Some(
                "Configured pre-shared key; media crypto not installed here".to_string(),
            ),
            srtp_profile,
        }
    }

    async fn process_client_packet(
        &self,
        addr: SocketAddr,
        _data: &[u8],
    ) -> Result<(), SecurityError> {
        debug!(
            "SRTP-only server: No client packet processing needed for pre-shared keys from {}",
            addr
        );
        Ok(())
    }

    async fn is_ready(&self) -> Result<bool, SecurityError> {
        let socket_set = self.socket.read().await.is_some();

        debug!("SRTP-only server security context ready: {}", socket_set);
        debug!("  - Socket set: {}", socket_set);

        Ok(socket_set)
    }

    /// Get the security configuration
    fn get_config(&self) -> &ServerSecurityConfig {
        &self.config
    }
}

/// Configuration-only SRTP client companion for server-side client handling.
///
/// It does not own or install media crypto and cannot by itself attest that
/// the client connection is secure.
pub struct SrtpServerClientContext {
    /// Client address
    addr: SocketAddr,
    /// Names derived only after the complete profile list validates.
    advertised_profiles: Vec<String>,
    /// Socket handle
    socket: Arc<RwLock<Option<SocketHandle>>>,
}

impl SrtpServerClientContext {
    /// Create a new SRTP server client context
    pub async fn new(
        addr: SocketAddr,
        config: ServerSecurityConfig,
    ) -> Result<Self, SecurityError> {
        config.validate()?;
        let advertised_profiles =
            crate::api::common::config::implemented_srtp_profile_names(&config.srtp_profiles)?;
        Ok(Self {
            addr,
            advertised_profiles,
            socket: Arc::new(RwLock::new(None)),
        })
    }
}

#[async_trait]
impl ClientSecurityContext for SrtpServerClientContext {
    async fn set_socket(&self, socket: SocketHandle) -> Result<(), SecurityError> {
        let mut socket_lock = self.socket.write().await;
        *socket_lock = Some(socket);
        debug!("SRTP-only server client {}: Set socket", self.addr);
        Ok(())
    }

    async fn get_remote_fingerprint(&self) -> Result<Option<String>, SecurityError> {
        Ok(None) // No fingerprint for pre-shared keys
    }

    async fn get_fingerprint(&self) -> Result<String, SecurityError> {
        Err(SecurityError::Configuration(
            "Fingerprints not used with pre-shared key SRTP".to_string(),
        ))
    }

    async fn get_fingerprint_algorithm(&self) -> Result<String, SecurityError> {
        Err(SecurityError::Configuration(
            "Fingerprint algorithm not used with pre-shared key SRTP".to_string(),
        ))
    }

    async fn close(&self) -> Result<(), SecurityError> {
        debug!("SRTP-only server client {}: Closing", self.addr);
        Ok(())
    }

    fn is_secure(&self) -> bool {
        false
    }

    fn get_security_info(&self) -> SecurityInfo {
        let crypto_suites = self.advertised_profiles.clone();
        let srtp_profile = crypto_suites.first().cloned();

        SecurityInfo {
            mode: SecurityMode::Srtp,
            fingerprint: None,
            fingerprint_algorithm: None,
            crypto_suites,
            key_params: Some(
                "Configured pre-shared key; media crypto not installed here".to_string(),
            ),
            srtp_profile,
        }
    }

    async fn wait_for_handshake(&self) -> Result<(), SecurityError> {
        debug!(
            "SRTP-only server client {}: No handshake wait needed",
            self.addr
        );
        Ok(())
    }

    async fn is_handshake_complete(&self) -> Result<bool, SecurityError> {
        Ok(true) // Always complete for pre-shared keys
    }

    async fn process_dtls_packet(&self, _data: &[u8]) -> Result<(), SecurityError> {
        debug!(
            "SRTP-only server client {}: No DTLS packet processing needed",
            self.addr
        );
        Ok(())
    }

    async fn start_handshake_with_remote(
        &self,
        _remote_addr: SocketAddr,
    ) -> Result<(), SecurityError> {
        debug!(
            "SRTP-only server client {}: No handshake needed for pre-shared keys",
            self.addr
        );
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
