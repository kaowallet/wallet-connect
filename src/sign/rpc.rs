//! Sign API JSON-RPC methods and their relay publish options (TTL, tag,
//! push prompt), as defined by the protocol.

use crate::relay::PublishOptions;
use crate::time::{FIFTEEN_MINUTES, FIVE_MINUTES, ONE_DAY, ONE_HOUR, THIRTY_SECONDS};

pub mod methods {
    pub const SESSION_PROPOSE: &str = "wc_sessionPropose";
    pub const SESSION_SETTLE: &str = "wc_sessionSettle";
    pub const SESSION_UPDATE: &str = "wc_sessionUpdate";
    pub const SESSION_EXTEND: &str = "wc_sessionExtend";
    pub const SESSION_REQUEST: &str = "wc_sessionRequest";
    pub const SESSION_EVENT: &str = "wc_sessionEvent";
    pub const SESSION_DELETE: &str = "wc_sessionDelete";
    pub const SESSION_PING: &str = "wc_sessionPing";
    pub const SESSION_AUTHENTICATE: &str = "wc_sessionAuthenticate";
    pub const PAIRING_PING: &str = "wc_pairingPing";
    pub const PAIRING_DELETE: &str = "wc_pairingDelete";
}

/// Publish options for each leg of a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodOptions {
    pub request: PublishOptions,
    pub response: PublishOptions,
    /// Used when a wallet rejects a proposal.
    pub reject: Option<PublishOptions>,
    /// Used when a proposal is rejected automatically (invalid params).
    pub auto_reject: Option<PublishOptions>,
}

const fn o(ttl: u64, tag: u32, prompt: bool) -> PublishOptions {
    PublishOptions { ttl, tag, prompt }
}

const fn pair(ttl: u64, tag: u32, prompt: bool) -> MethodOptions {
    MethodOptions {
        request: o(ttl, tag, prompt),
        response: o(ttl, tag + 1, false),
        reject: None,
        auto_reject: None,
    }
}

/// Options for `method`, or `None` for methods this crate doesn't know.
pub fn options(method: &str) -> Option<MethodOptions> {
    use methods::*;
    Some(match method {
        PAIRING_DELETE => pair(ONE_DAY, 1000, false),
        PAIRING_PING => pair(THIRTY_SECONDS, 1002, false),
        SESSION_PROPOSE => MethodOptions {
            reject: Some(o(FIVE_MINUTES, 1120, false)),
            auto_reject: Some(o(FIVE_MINUTES, 1121, false)),
            ..pair(FIVE_MINUTES, 1100, true)
        },
        SESSION_SETTLE => pair(FIVE_MINUTES, 1102, false),
        SESSION_UPDATE => pair(ONE_DAY, 1104, false),
        SESSION_EXTEND => pair(ONE_DAY, 1106, false),
        SESSION_REQUEST => pair(FIFTEEN_MINUTES, 1108, true),
        SESSION_EVENT => pair(FIVE_MINUTES, 1110, true),
        SESSION_DELETE => pair(ONE_DAY, 1112, false),
        SESSION_PING => pair(ONE_DAY, 1114, false),
        SESSION_AUTHENTICATE => MethodOptions {
            reject: Some(o(FIVE_MINUTES, 1118, false)),
            auto_reject: Some(o(FIVE_MINUTES, 1119, false)),
            ..pair(ONE_HOUR, 1116, true)
        },
        _ => return None,
    })
}

/// Options for unknown methods (tag 0), as in the reference SDK.
pub const UNREGISTERED: MethodOptions = pair(ONE_DAY, 0, false);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_match_the_spec() {
        let req_tag = |m| options(m).unwrap().request.tag;
        let res_tag = |m| options(m).unwrap().response.tag;
        assert_eq!(
            (
                req_tag(methods::SESSION_PROPOSE),
                res_tag(methods::SESSION_PROPOSE)
            ),
            (1100, 1101)
        );
        assert_eq!(
            (
                req_tag(methods::SESSION_REQUEST),
                res_tag(methods::SESSION_REQUEST)
            ),
            (1108, 1109)
        );
        assert_eq!(
            (
                req_tag(methods::SESSION_PING),
                res_tag(methods::SESSION_PING)
            ),
            (1114, 1115)
        );
        assert_eq!(
            (
                req_tag(methods::PAIRING_PING),
                res_tag(methods::PAIRING_PING)
            ),
            (1002, 1003)
        );
        let propose = options(methods::SESSION_PROPOSE).unwrap();
        assert!(propose.request.prompt && !propose.response.prompt);
        assert_eq!(propose.reject.unwrap().tag, 1120);
        assert_eq!(propose.auto_reject.unwrap().tag, 1121);
        assert_eq!(options(methods::SESSION_REQUEST).unwrap().request.ttl, 900);
        assert!(options("wc_nope").is_none());
    }
}
