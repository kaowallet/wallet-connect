//! The error codes WalletConnect peers exchange.

use std::fmt;

use crate::rpc::ErrorObject;

/// SDK errors: the codes a peer receives when a request or proposal is
/// rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SdkError {
    InvalidMethod,
    InvalidEvent,
    InvalidUpdateRequest,
    InvalidExtendRequest,
    InvalidSessionSettleRequest,
    UnauthorizedMethod,
    UnauthorizedEvent,
    UnauthorizedUpdateRequest,
    UnauthorizedExtendRequest,
    UserRejected,
    UserRejectedChains,
    UserRejectedMethods,
    UserRejectedEvents,
    UnsupportedChains,
    UnsupportedMethods,
    UnsupportedEvents,
    UnsupportedAccounts,
    UnsupportedNamespaceKey,
    UserDisconnected,
    SessionSettlementFailed,
    WcMethodUnsupported,
}

impl SdkError {
    pub const ALL: [SdkError; 21] = [
        SdkError::InvalidMethod,
        SdkError::InvalidEvent,
        SdkError::InvalidUpdateRequest,
        SdkError::InvalidExtendRequest,
        SdkError::InvalidSessionSettleRequest,
        SdkError::UnauthorizedMethod,
        SdkError::UnauthorizedEvent,
        SdkError::UnauthorizedUpdateRequest,
        SdkError::UnauthorizedExtendRequest,
        SdkError::UserRejected,
        SdkError::UserRejectedChains,
        SdkError::UserRejectedMethods,
        SdkError::UserRejectedEvents,
        SdkError::UnsupportedChains,
        SdkError::UnsupportedMethods,
        SdkError::UnsupportedEvents,
        SdkError::UnsupportedAccounts,
        SdkError::UnsupportedNamespaceKey,
        SdkError::UserDisconnected,
        SdkError::SessionSettlementFailed,
        SdkError::WcMethodUnsupported,
    ];

    pub const fn code(self) -> i64 {
        match self {
            SdkError::InvalidMethod => 1001,
            SdkError::InvalidEvent => 1002,
            SdkError::InvalidUpdateRequest => 1003,
            SdkError::InvalidExtendRequest => 1004,
            SdkError::InvalidSessionSettleRequest => 1005,
            SdkError::UnauthorizedMethod => 3001,
            SdkError::UnauthorizedEvent => 3002,
            SdkError::UnauthorizedUpdateRequest => 3003,
            SdkError::UnauthorizedExtendRequest => 3004,
            SdkError::UserRejected => 5000,
            SdkError::UserRejectedChains => 5001,
            SdkError::UserRejectedMethods => 5002,
            SdkError::UserRejectedEvents => 5003,
            SdkError::UnsupportedChains => 5100,
            SdkError::UnsupportedMethods => 5101,
            SdkError::UnsupportedEvents => 5102,
            SdkError::UnsupportedAccounts => 5103,
            SdkError::UnsupportedNamespaceKey => 5104,
            SdkError::UserDisconnected => 6000,
            SdkError::SessionSettlementFailed => 7000,
            SdkError::WcMethodUnsupported => 10001,
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            SdkError::InvalidMethod => "Invalid method.",
            SdkError::InvalidEvent => "Invalid event.",
            SdkError::InvalidUpdateRequest => "Invalid update request.",
            SdkError::InvalidExtendRequest => "Invalid extend request.",
            SdkError::InvalidSessionSettleRequest => "Invalid session settle request.",
            SdkError::UnauthorizedMethod => "Unauthorized method.",
            SdkError::UnauthorizedEvent => "Unauthorized event.",
            SdkError::UnauthorizedUpdateRequest => "Unauthorized update request.",
            SdkError::UnauthorizedExtendRequest => "Unauthorized extend request.",
            SdkError::UserRejected => "User rejected.",
            SdkError::UserRejectedChains => "User rejected chains.",
            SdkError::UserRejectedMethods => "User rejected methods.",
            SdkError::UserRejectedEvents => "User rejected events.",
            SdkError::UnsupportedChains => "Unsupported chains.",
            SdkError::UnsupportedMethods => "Unsupported methods.",
            SdkError::UnsupportedEvents => "Unsupported events.",
            SdkError::UnsupportedAccounts => "Unsupported accounts.",
            SdkError::UnsupportedNamespaceKey => "Unsupported namespace key.",
            SdkError::UserDisconnected => "User disconnected.",
            SdkError::SessionSettlementFailed => "Session settlement failed.",
            SdkError::WcMethodUnsupported => "Unsupported wc_ method.",
        }
    }

    pub fn from_code(code: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.code() == code)
    }

    /// The bare error object, e.g. `{code: 5000, message: "User rejected."}`.
    pub fn error(self) -> ErrorObject {
        ErrorObject::new(self.code(), self.message())
    }

    /// The error object with extra context appended to the message.
    pub fn with_context(self, context: impl fmt::Display) -> ErrorObject {
        ErrorObject::new(self.code(), format!("{} {context}", self.message()))
    }
}

impl From<SdkError> for ErrorObject {
    fn from(e: SdkError) -> Self {
        e.error()
    }
}

/// Internal errors of the reference SDK that also travel over the wire
/// (mostly as validation failures).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InternalError {
    NoMatchingKey,
    MissingOrInvalid,
    Expired,
    MismatchedTopic,
    NonConformingNamespaces,
}

impl InternalError {
    pub const fn code(self) -> i64 {
        match self {
            InternalError::NoMatchingKey => 2,
            InternalError::MissingOrInvalid => 5,
            InternalError::Expired => 6,
            InternalError::MismatchedTopic => 8,
            InternalError::NonConformingNamespaces => 9,
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            InternalError::NoMatchingKey => "No matching key.",
            InternalError::MissingOrInvalid => "Missing or invalid.",
            InternalError::Expired => "Expired.",
            InternalError::MismatchedTopic => "Mismatched topic.",
            InternalError::NonConformingNamespaces => "Non conforming namespaces.",
        }
    }

    pub fn with_context(self, context: impl fmt::Display) -> ErrorObject {
        ErrorObject::new(self.code(), format!("{} {context}", self.message()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_roundtrip() {
        for e in SdkError::ALL {
            assert_eq!(SdkError::from_code(e.code()), Some(e));
        }
        assert_eq!(
            SdkError::UserRejected.error(),
            ErrorObject::new(5000, "User rejected.")
        );
        assert_eq!(
            SdkError::UnsupportedChains.with_context("eip155:9"),
            ErrorObject::new(5100, "Unsupported chains. eip155:9")
        );
    }
}
