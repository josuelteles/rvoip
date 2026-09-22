//! `GenericResponseBuilder` — SIP_API_DESIGN_2 §3.4.

use std::sync::Arc;

use rvoip_sip_core::types::Method;
use rvoip_sip_dialog::transaction::TransactionKey;

use crate::api::handle::CallId;
use crate::api::headers::{take_staged, BuilderHeaderState, SipRequestOptions};
use crate::api::incoming::ExactResponseObligation;
use crate::api::unified::UnifiedCoordinator;
use crate::errors::{Result, SessionError};
use crate::session_registry::SessionRegistryHandle;

/// Builds and sends a generic non-2xx final response (3xx/4xx/5xx/6xx).
pub struct GenericResponseBuilder {
    coord: Arc<UnifiedCoordinator>,
    call_id: CallId,
    lifecycle_handle: Option<SessionRegistryHandle>,
    method: Method,
    status: u16,
    reason: Option<String>,
    contacts: Vec<String>,
    exact_transaction: Option<TransactionKey>,
    response_obligation: Option<Arc<ExactResponseObligation>>,
    state: BuilderHeaderState,
}

impl GenericResponseBuilder {
    /// `method` is the request method this response is for — drives
    /// `HeaderPolicy::classify` so attaching e.g. `Event:` on a
    /// NOTIFY-shaped `respond_builder(401)` raises the appropriate
    /// dedicated-setter error. Per SIP_API_DESIGN_2 §3.4 every
    /// response builder must thread the inbound method through.
    pub(crate) fn new(
        coord: Arc<UnifiedCoordinator>,
        call_id: CallId,
        method: Method,
        status: u16,
    ) -> Result<Self> {
        let lifecycle_handle = coord.helpers.state_machine.store.lifecycle_handle(&call_id);
        Self::new_captured(coord, call_id, lifecycle_handle, method, status)
    }

    pub(crate) fn new_exact(
        coord: Arc<UnifiedCoordinator>,
        call_id: CallId,
        lifecycle_handle: SessionRegistryHandle,
        method: Method,
        status: u16,
    ) -> Result<Self> {
        Self::new_captured(coord, call_id, Some(lifecycle_handle), method, status)
    }

    pub(crate) fn new_captured(
        coord: Arc<UnifiedCoordinator>,
        call_id: CallId,
        lifecycle_handle: Option<SessionRegistryHandle>,
        method: Method,
        status: u16,
    ) -> Result<Self> {
        // Status range guard per §3.4: 3xx/4xx/5xx/6xx only.
        if !(300..=699).contains(&status) {
            return Err(SessionError::InvalidInput(format!(
                "GenericResponseBuilder status must be 3xx/4xx/5xx/6xx, got {status}"
            )));
        }
        Ok(Self {
            coord,
            call_id,
            lifecycle_handle,
            method,
            status,
            reason: None,
            contacts: Vec::new(),
            exact_transaction: None,
            response_obligation: None,
            state: BuilderHeaderState::default(),
        })
    }

    pub(crate) fn new_in_dialog(
        coord: Arc<UnifiedCoordinator>,
        call_id: CallId,
        method: Method,
        transaction_id: TransactionKey,
        status: u16,
        response_obligation: Arc<ExactResponseObligation>,
    ) -> Result<Self> {
        if !(200..=699).contains(&status) {
            return Err(SessionError::InvalidInput(format!(
                "exact in-dialog response status must be 2xx/3xx/4xx/5xx/6xx, got {status}"
            )));
        }
        if !transaction_id.is_server()
            || transaction_id.method() != &method
            || method == Method::Invite
        {
            return Err(SessionError::InvalidInput(
                "exact in-dialog response requires the matching non-INVITE server transaction"
                    .to_string(),
            ));
        }
        Ok(Self {
            coord,
            call_id,
            lifecycle_handle: None,
            method,
            status,
            reason: None,
            contacts: Vec::new(),
            exact_transaction: Some(transaction_id),
            response_obligation: Some(response_obligation),
            state: BuilderHeaderState::default(),
        })
    }

    /// Set the response reason phrase (defaults to a status-derived value).
    pub fn with_reason(mut self, r: impl Into<String>) -> Self {
        self.reason = Some(r.into());
        self
    }

    /// Add a `Contact` URI to a 3xx to the initial INVITE.
    ///
    /// Contacts are only what the application gives: a 3xx without any goes
    /// out without a `Contact` header. RFC 3261 §21.3 recommends one in
    /// 300-305, so a redirect should normally carry at least one. Other
    /// statuses reject contacts at [`Self::send`].
    pub fn with_contact(mut self, uri: impl Into<String>) -> Self {
        self.contacts.push(uri.into());
        self
    }

    /// Add several `Contact` URIs to a 3xx. See [`Self::with_contact`].
    pub fn with_contacts<I, S>(mut self, uris: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.contacts.extend(uris.into_iter().map(Into::into));
        self
    }

    /// Send the response, routing 3xx through the redirect path and
    /// 4xx/5xx/6xx through the reject path.
    pub async fn send(mut self) -> Result<()> {
        let reason = self
            .reason
            .take()
            .unwrap_or_else(|| status_reason(self.status));
        let extras = take_staged(&mut self.state);
        if !self.contacts.is_empty()
            && (self.exact_transaction.is_some() || !(300..=399).contains(&self.status))
        {
            return Err(SessionError::InvalidInput(format!(
                "Contact URIs are only accepted for a 3xx to the initial INVITE, got {}",
                self.status
            )));
        }

        if let Some(transaction_id) = self.exact_transaction.take() {
            let obligation = self.response_obligation.take().ok_or_else(|| {
                SessionError::InternalError(
                    "exact in-dialog response has no response obligation".to_string(),
                )
            })?;
            let claim = obligation.claim()?;
            let result = self
                .coord
                .dialog_adapter()
                .send_response_with_options_for_transaction_classified(
                    &self.call_id,
                    &transaction_id,
                    self.status,
                    None,
                    extras,
                )
                .await;
            return match result {
                Ok(rvoip_sip_dialog::FinalResponseCompletionDisposition::WrittenSuccessTerminal) => {
                    claim.complete();
                    Ok(())
                }
                Ok(disposition) => {
                    claim.complete();
                    Err(SessionError::InternalError(format!(
                        "exact response returned nonterminal success disposition: {disposition:?}"
                    )))
                }
                Err(error)
                    if error.disposition
                        == rvoip_sip_dialog::FinalResponseCompletionDisposition::ZeroWireRetryable =>
                {
                    claim.release_after_failure();
                    Err(SessionError::DialogError(format!(
                        "Failed to send exact in-dialog response: {}",
                        error.source
                    )))
                }
                Err(error) => {
                    claim.complete();
                    Err(SessionError::DialogError(format!(
                        "Exact in-dialog response became wire-unknown and will not be retried: {}",
                        error.source
                    )))
                }
            };
        }

        let lifecycle_handle = self
            .lifecycle_handle
            .as_ref()
            .ok_or_else(|| SessionError::SessionNotFound(self.call_id.to_string()))?;

        // 3xx → redirect path; 4xx/5xx/6xx → reject path.
        if (300..=399).contains(&self.status) {
            self.coord
                .resolve_incoming_final_exact(
                    lifecycle_handle,
                    Some(crate::api::events::Event::CallFailed {
                        call_id: self.call_id.clone(),
                        status_code: self.status,
                        reason,
                    }),
                    self.coord.helpers.redirect_call_with_extras_exact(
                        lifecycle_handle,
                        self.status,
                        std::mem::take(&mut self.contacts),
                        extras,
                    ),
                )
                .await
        } else {
            self.coord
                .resolve_incoming_final_exact(
                    lifecycle_handle,
                    Some(crate::api::events::Event::CallFailed {
                        call_id: self.call_id.clone(),
                        status_code: self.status,
                        reason: reason.clone(),
                    }),
                    self.coord.helpers.reject_call_with_extras_exact(
                        lifecycle_handle,
                        self.status,
                        &reason,
                        extras,
                    ),
                )
                .await
        }
    }
}

impl SipRequestOptions for GenericResponseBuilder {
    fn method(&self) -> Method {
        // Returns the request method threaded through the constructor,
        // not a hardcoded INVITE — SIP_API_DESIGN_2 §3.4 requires the
        // response builder's policy classification to track the
        // underlying request method.
        self.method.clone()
    }
    fn header_state_mut(&mut self) -> &mut BuilderHeaderState {
        &mut self.state
    }
    fn header_state(&self) -> &BuilderHeaderState {
        &self.state
    }
}

/// Reason phrase of `status`, used when the application gave none.
pub(crate) fn status_reason(status: u16) -> String {
    rvoip_sip_core::StatusCode::from_u16(status)
        .map(|code| code.reason_phrase().to_string())
        .unwrap_or_default()
}
