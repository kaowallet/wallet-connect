//! Namespace validation and helpers.
//!
//! The rules follow the reference SDK so that both sides agree on what is
//! acceptable:
//!
//! * proposal namespaces either list CAIP-2 `chains` or are keyed by a chain
//!   (`"eip155:1": {…}`);
//! * session namespaces list CAIP-10 `accounts`, from which the session's
//!   chains are derived;
//! * session namespaces *conform* to the required namespaces when every
//!   required namespace key, chain, method and event is granted.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::errors::{InternalError, SdkError};
use super::types::{ProposalNamespace, ProposalNamespaces, SessionNamespace, SessionNamespaces};
use crate::caip::{AccountId, ChainId};
use crate::rpc::ErrorObject;

fn is_chain_id(s: &str) -> bool {
    s.parse::<ChainId>().is_ok()
}

fn is_account_id(s: &str) -> bool {
    s.parse::<AccountId>().is_ok()
}

/// `eip155:1:0xab…` → `eip155:1`.
pub fn account_chain(account: &str) -> String {
    let mut parts = account.splitn(3, ':');
    match (parts.next(), parts.next()) {
        (Some(ns), Some(reference)) => format!("{ns}:{reference}"),
        _ => account.to_owned(),
    }
}

/// `eip155:1` → `eip155`; `eip155` → `eip155`.
pub fn namespace_key(key: &str) -> &str {
    key.split(':').next().unwrap_or(key)
}

/// Union of `a` and `b`, preserving first-seen order.
pub fn merge_arrays(a: &[String], b: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(a.len() + b.len());
    for s in a.iter().chain(b) {
        if !out.contains(s) {
            out.push(s.clone());
        }
    }
    out
}

fn is_subset(a: &[String], b: &[String]) -> bool {
    a.iter().all(|x| b.contains(x))
}

/// Chains of a proposal namespace: its `chains`, or the key itself when it
/// is chain-scoped.
pub fn proposal_namespace_chains(key: &str, ns: &ProposalNamespace) -> Vec<String> {
    if key.contains(':') {
        vec![key.to_owned()]
    } else {
        ns.chains.clone().unwrap_or_default()
    }
}

/// Methods and events must be non-blank strings, as in the reference SDK's
/// `isValidActions`.
fn validate_actions(
    methods: &[String],
    events: &[String],
    context: &str,
) -> Result<(), ErrorObject> {
    let blank = |names: &[String]| names.iter().any(|n| n.trim().is_empty());
    if blank(methods) {
        return Err(SdkError::UnsupportedMethods.with_context(format!(
            "{context}: methods should be an array of non-empty strings or empty array for no methods"
        )));
    }
    if blank(events) {
        return Err(SdkError::UnsupportedEvents.with_context(format!(
            "{context}: events should be an array of non-empty strings or empty array for no events"
        )));
    }
    Ok(())
}

/// Validate proposal (required or optional) namespaces.
pub fn validate_proposal_namespaces(
    namespaces: &ProposalNamespaces,
    context: &str,
) -> Result<(), ErrorObject> {
    for (key, ns) in namespaces {
        validate_actions(&ns.methods, &ns.events, context)?;
        let chains = ns.chains.as_deref().unwrap_or_default();
        if !chains.is_empty() {
            if let Some(bad) = chains.iter().find(|c| !is_chain_id(c)) {
                return Err(SdkError::UnsupportedChains.with_context(format!(
                    "{context}: chain {bad} should conform to \"namespace:chainId\" format"
                )));
            }
            if chains
                .iter()
                .any(|c| namespace_key(c) != namespace_key(key))
            {
                return Err(SdkError::UnsupportedNamespaceKey.with_context(format!(
                    "{context}: chains of `{key}` must belong to that namespace"
                )));
            }
        } else if !is_chain_id(key) {
            return Err(SdkError::UnsupportedChains.with_context(format!(
                "{context}: chains must be defined as \"namespace:chainId\" e.g. \"eip155:1\": {{...}} in the namespace key OR as an array of CAIP-2 chainIds e.g. eip155: {{ chains: [\"eip155:1\", \"eip155:5\"] }}"
            )));
        }
    }
    Ok(())
}

/// Validate session namespaces: non-empty, CAIP-10 accounts, accounts
/// belonging to their namespace (and chain, for chain-scoped keys).
pub fn validate_session_namespaces(
    namespaces: &SessionNamespaces,
    context: &str,
) -> Result<(), ErrorObject> {
    if namespaces.is_empty() {
        return Err(InternalError::MissingOrInvalid.with_context(format!(
            "{context}: namespaces should be an object with data"
        )));
    }
    for (key, ns) in namespaces {
        validate_actions(&ns.methods, &ns.events, context)?;
        if let Some(bad) = ns.accounts.iter().find(|a| !is_account_id(a)) {
            return Err(SdkError::UnsupportedAccounts.with_context(format!(
                "{context}: account {bad} should conform to \"namespace:chainId:address\" format"
            )));
        }
        if let Some(bad) = ns
            .accounts
            .iter()
            .find(|a| namespace_key(a) != namespace_key(key))
        {
            return Err(SdkError::UnsupportedAccounts.with_context(format!(
                "{context}: account {bad} does not belong to namespace {key}"
            )));
        }
        if let Some(chains) = &ns.chains
            && let Some(bad) = chains.iter().find(|c| !is_chain_id(c))
        {
            return Err(SdkError::UnsupportedChains.with_context(format!(
                "{context}: chain {bad} should conform to \"namespace:chainId\" format"
            )));
        }
    }
    Ok(())
}

/// Unique chains of the session's accounts.
pub fn session_chains(namespaces: &SessionNamespaces) -> Vec<String> {
    let mut chains: Vec<String> = Vec::new();
    for ns in namespaces.values() {
        for account in &ns.accounts {
            let chain = account_chain(account);
            if !chains.contains(&chain) {
                chains.push(chain);
            }
        }
    }
    chains
}

fn namespaces_for_chain<'a>(
    namespaces: &'a SessionNamespaces,
    chain: &'a str,
) -> impl Iterator<Item = &'a SessionNamespace> + 'a {
    namespaces
        .values()
        .filter(move |ns| ns.accounts.iter().any(|a| account_chain(a) == chain))
}

/// Methods the session allows on `chain`.
pub fn session_methods_for_chain(namespaces: &SessionNamespaces, chain: &str) -> Vec<String> {
    namespaces_for_chain(namespaces, chain)
        .flat_map(|ns| ns.methods.iter().cloned())
        .collect()
}

/// Events the session allows on `chain`.
pub fn session_events_for_chain(namespaces: &SessionNamespaces, chain: &str) -> Vec<String> {
    namespaces_for_chain(namespaces, chain)
        .flat_map(|ns| ns.events.iter().cloned())
        .collect()
}

/// Whether `chain` is one of the session's chains.
pub fn session_has_chain(namespaces: &SessionNamespaces, chain: &str) -> bool {
    is_chain_id(chain) && session_chains(namespaces).iter().any(|c| c == chain)
}

/// Check that `approved` satisfies `required`.
pub fn ensure_conforming(
    required: &ProposalNamespaces,
    approved: &SessionNamespaces,
    context: &str,
) -> Result<(), ErrorObject> {
    let error = |m: String| InternalError::NonConformingNamespaces.with_context(m);

    // Per-chain view of the required namespaces.
    let mut parsed_required: BTreeMap<String, (&[String], &[String])> = BTreeMap::new();
    for (key, ns) in required {
        for chain in proposal_namespace_chains(key, ns) {
            parsed_required.insert(chain, (&ns.methods, &ns.events));
        }
    }
    // Per-chain view of the approved namespaces.
    let mut parsed_approved: BTreeMap<String, (&[String], &[String])> = BTreeMap::new();
    for (key, ns) in approved {
        if key.contains(':') {
            parsed_approved.insert(key.clone(), (&ns.methods, &ns.events));
        } else {
            for account in &ns.accounts {
                parsed_approved.insert(account_chain(account), (&ns.methods, &ns.events));
            }
        }
    }

    let approved_keys: Vec<&str> = approved.keys().map(|k| namespace_key(k)).collect();
    let missing: Vec<&str> = required
        .keys()
        .map(|k| namespace_key(k))
        .filter(|k| !approved_keys.contains(k))
        .collect();
    if !missing.is_empty() {
        return Err(error(format!(
            "{context} namespaces keys don't satisfy requiredNamespaces. Required: {} Received: {}",
            missing.join(","),
            approved.keys().cloned().collect::<Vec<_>>().join(",")
        )));
    }

    let missing_chains: Vec<&String> = parsed_required
        .keys()
        .filter(|c| !parsed_approved.contains_key(*c))
        .collect();
    if !missing_chains.is_empty() {
        return Err(error(format!(
            "{context} namespaces chains don't satisfy required namespaces. Missing: {}",
            missing_chains
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )));
    }

    for (key, ns) in approved {
        if key.contains(':') && !ns.accounts.iter().any(|a| account_chain(a) == *key) {
            return Err(error(format!(
                "{context} namespaces accounts don't satisfy namespace accounts for {key}"
            )));
        }
    }

    for (chain, (methods, events)) in &parsed_required {
        let (approved_methods, approved_events) = parsed_approved[chain];
        if !is_subset(methods, approved_methods) {
            return Err(error(format!(
                "{context} namespaces methods don't satisfy namespace methods for {chain}"
            )));
        }
        if !is_subset(events, approved_events) {
            return Err(error(format!(
                "{context} namespaces events don't satisfy namespace events for {chain}"
            )));
        }
    }
    Ok(())
}

/// Fold chain-scoped keys into their namespace:
/// `{"eip155:1": {..}, "eip155:10": {..}}` → `{"eip155": {chains: ["eip155:1", "eip155:10"], ..}}`.
pub fn normalize(namespaces: &ProposalNamespaces) -> ProposalNamespaces {
    let mut out: ProposalNamespaces = BTreeMap::new();
    for (key, ns) in namespaces {
        let chains = proposal_namespace_chains(key, ns);
        let entry = out.entry(namespace_key(key).to_owned()).or_default();
        entry.chains = Some(merge_arrays(
            &chains,
            entry.chains.as_deref().unwrap_or_default(),
        ));
        entry.methods = merge_arrays(&ns.methods, &entry.methods);
        entry.events = merge_arrays(&ns.events, &entry.events);
    }
    out
}

/// Required and optional namespaces merged into one normalized set.
pub fn merge_required_and_optional(
    required: &ProposalNamespaces,
    optional: &ProposalNamespaces,
) -> ProposalNamespaces {
    let required = normalize(required);
    let mut merged = required.clone();
    for (key, ns) in normalize(optional) {
        let entry = merged.entry(key).or_default();
        entry.chains = Some(merge_arrays(
            entry.chains.as_deref().unwrap_or_default(),
            ns.chains.as_deref().unwrap_or_default(),
        ));
        entry.methods = merge_arrays(&entry.methods, &ns.methods);
        entry.events = merge_arrays(&entry.events, &ns.events);
    }
    merged
}

/// What a wallet supports in one namespace, for [`build_approved_namespaces`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SupportedNamespace {
    pub chains: Vec<String>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
    pub accounts: Vec<String>,
}

/// Build the session namespaces a wallet approves: everything required, plus
/// whatever optional chains/methods/events it also supports.
///
/// Fails when the wallet does not support everything that is required, or
/// when a supported chain has no account.
pub fn build_approved_namespaces(
    required: &ProposalNamespaces,
    optional: &ProposalNamespaces,
    supported: &BTreeMap<String, SupportedNamespace>,
) -> Result<SessionNamespaces, ErrorObject> {
    let mut all: SessionNamespaces = BTreeMap::new();
    for (key, s) in supported {
        if let Some(chain) = s
            .chains
            .iter()
            .find(|c| !s.accounts.iter().any(|a| account_chain(a) == **c))
        {
            return Err(SdkError::UnsupportedAccounts.with_context(format!(
                "no accounts provided for chain {chain} in namespace {key}"
            )));
        }
        all.insert(
            key.clone(),
            SessionNamespace {
                chains: Some(s.chains.clone()),
                accounts: s.accounts.clone(),
                methods: s.methods.clone(),
                events: s.events.clone(),
            },
        );
    }
    ensure_conforming(required, &all, "approve()")?;
    if required.is_empty() && optional.is_empty() {
        return Ok(all);
    }

    let accounts_for = |s: &SupportedNamespace, chains: &[String]| -> Vec<String> {
        chains
            .iter()
            .flat_map(|chain| {
                s.accounts
                    .iter()
                    .filter(move |a| account_chain(a) == *chain)
                    .cloned()
            })
            .collect()
    };

    let mut approved: SessionNamespaces = BTreeMap::new();
    for (key, req) in normalize(required) {
        let s = &supported[&key]; // guaranteed by ensure_conforming
        let req_chains = req.chains.unwrap_or_default();
        let chains: Vec<String> = s
            .chains
            .iter()
            .filter(|c| req_chains.contains(c))
            .cloned()
            .collect();
        let methods: Vec<String> = s
            .methods
            .iter()
            .filter(|m| req.methods.contains(m))
            .cloned()
            .collect();
        let events: Vec<String> = s
            .events
            .iter()
            .filter(|e| req.events.contains(e))
            .cloned()
            .collect();
        let accounts = accounts_for(s, &chains);
        approved.insert(
            key,
            SessionNamespace {
                chains: Some(chains),
                accounts,
                methods,
                events,
            },
        );
    }
    for (key, opt) in normalize(optional) {
        let Some(s) = supported.get(&key) else {
            continue;
        };
        let opt_chains = opt.chains.unwrap_or_default();
        let chains: Vec<String> = opt_chains
            .iter()
            .filter(|c| s.chains.contains(c))
            .cloned()
            .collect();
        let methods: Vec<String> = s
            .methods
            .iter()
            .filter(|m| opt.methods.contains(m))
            .cloned()
            .collect();
        let events: Vec<String> = s
            .events
            .iter()
            .filter(|e| opt.events.contains(e))
            .cloned()
            .collect();
        let accounts = accounts_for(s, &chains);
        let entry = approved.entry(key).or_default();
        entry.chains = Some(merge_arrays(
            entry.chains.as_deref().unwrap_or_default(),
            &chains,
        ));
        entry.methods = merge_arrays(&entry.methods, &methods);
        entry.events = merge_arrays(&entry.events, &events);
        entry.accounts = merge_arrays(&entry.accounts, &accounts);
    }
    approved.retain(|_, ns| {
        !ns.accounts.is_empty() && ns.chains.as_ref().is_none_or(|c| !c.is_empty())
    });
    Ok(approved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn eip155_required() -> ProposalNamespaces {
        BTreeMap::from([(
            "eip155".to_owned(),
            ProposalNamespace::new(["eip155:1"], ["personal_sign"], ["accountsChanged"]),
        )])
    }

    fn session(accounts: &[&str], methods: &[&str], events: &[&str]) -> SessionNamespaces {
        BTreeMap::from([(
            "eip155".to_owned(),
            SessionNamespace {
                chains: None,
                accounts: s(accounts),
                methods: s(methods),
                events: s(events),
            },
        )])
    }

    #[test]
    fn proposal_namespace_validation() {
        assert!(validate_proposal_namespaces(&eip155_required(), "t").is_ok());
        let inline: ProposalNamespaces = BTreeMap::from([(
            "eip155:1".to_owned(),
            ProposalNamespace {
                chains: None,
                methods: s(&["eth_sign"]),
                events: vec![],
            },
        )]);
        assert!(validate_proposal_namespaces(&inline, "t").is_ok());

        let no_chains: ProposalNamespaces =
            BTreeMap::from([("eip155".to_owned(), ProposalNamespace::default())]);
        assert_eq!(
            validate_proposal_namespaces(&no_chains, "t")
                .unwrap_err()
                .code,
            5100
        );

        let bad_chain: ProposalNamespaces = BTreeMap::from([(
            "eip155".to_owned(),
            ProposalNamespace::new(["eip155"], [], []),
        )]);
        assert_eq!(
            validate_proposal_namespaces(&bad_chain, "t")
                .unwrap_err()
                .code,
            5100
        );

        let wrong_ns: ProposalNamespaces = BTreeMap::from([(
            "eip155".to_owned(),
            ProposalNamespace::new(["solana:1"], [], []),
        )]);
        assert_eq!(
            validate_proposal_namespaces(&wrong_ns, "t")
                .unwrap_err()
                .code,
            5104
        );

        // Blank methods and events are rejected with their own codes.
        for (methods, events, code) in [(" ", "e", 5101), ("m", "", 5102), ("m", " ", 5102)] {
            let ns: ProposalNamespaces = BTreeMap::from([(
                "eip155".to_owned(),
                ProposalNamespace::new(["eip155:1"], [methods], [events]),
            )]);
            assert_eq!(
                validate_proposal_namespaces(&ns, "t").unwrap_err().code,
                code
            );
            let session = session(&["eip155:1:0xabc"], &[methods], &[events]);
            assert_eq!(
                validate_session_namespaces(&session, "t").unwrap_err().code,
                code
            );
        }
    }

    #[test]
    fn session_namespace_validation() {
        assert!(validate_session_namespaces(&session(&["eip155:1:0xabc"], &[], &[]), "t").is_ok());
        assert_eq!(
            validate_session_namespaces(&BTreeMap::new(), "t")
                .unwrap_err()
                .code,
            5
        );
        assert_eq!(
            validate_session_namespaces(&session(&["eip155:1"], &[], &[]), "t")
                .unwrap_err()
                .code,
            5103
        );
        assert_eq!(
            validate_session_namespaces(&session(&["solana:1:abc"], &[], &[]), "t")
                .unwrap_err()
                .code,
            5103
        );
    }

    #[test]
    fn conformance() {
        let req = eip155_required();
        let ok = session(
            &["eip155:1:0xabc", "eip155:10:0xabc"],
            &["personal_sign", "eth_sendTransaction"],
            &["accountsChanged", "chainChanged"],
        );
        assert!(ensure_conforming(&req, &ok, "t").is_ok());
        assert!(ensure_conforming(&BTreeMap::new(), &ok, "t").is_ok());

        let wrong_chain = session(
            &["eip155:10:0xabc"],
            &["personal_sign"],
            &["accountsChanged"],
        );
        assert_eq!(
            ensure_conforming(&req, &wrong_chain, "t").unwrap_err().code,
            9
        );
        let missing_method = session(&["eip155:1:0xabc"], &[], &["accountsChanged"]);
        assert_eq!(
            ensure_conforming(&req, &missing_method, "t")
                .unwrap_err()
                .code,
            9
        );
        let missing_event = session(&["eip155:1:0xabc"], &["personal_sign"], &[]);
        assert_eq!(
            ensure_conforming(&req, &missing_event, "t")
                .unwrap_err()
                .code,
            9
        );

        let other_ns: SessionNamespaces = BTreeMap::from([(
            "solana".to_owned(),
            SessionNamespace {
                accounts: s(&["solana:1:abc"]),
                ..Default::default()
            },
        )]);
        assert_eq!(ensure_conforming(&req, &other_ns, "t").unwrap_err().code, 9);

        // Inline chain keys in the session must be backed by an account.
        let inline: SessionNamespaces = BTreeMap::from([(
            "eip155:1".to_owned(),
            SessionNamespace {
                accounts: s(&["eip155:10:0xabc"]),
                methods: s(&["personal_sign"]),
                events: s(&["accountsChanged"]),
                chains: None,
            },
        )]);
        assert_eq!(ensure_conforming(&req, &inline, "t").unwrap_err().code, 9);
    }

    #[test]
    fn chain_scoped_queries() {
        let ns = session(&["eip155:1:0xabc"], &["personal_sign"], &["chainChanged"]);
        assert!(session_has_chain(&ns, "eip155:1"));
        assert!(!session_has_chain(&ns, "eip155:10"));
        assert_eq!(
            session_methods_for_chain(&ns, "eip155:1"),
            s(&["personal_sign"])
        );
        assert!(session_methods_for_chain(&ns, "eip155:10").is_empty());
        assert_eq!(
            session_events_for_chain(&ns, "eip155:1"),
            s(&["chainChanged"])
        );
    }

    #[test]
    fn normalize_and_merge() {
        let ns: ProposalNamespaces = BTreeMap::from([
            (
                "eip155:1".to_owned(),
                ProposalNamespace {
                    chains: None,
                    methods: s(&["a"]),
                    events: vec![],
                },
            ),
            (
                "eip155:10".to_owned(),
                ProposalNamespace {
                    chains: None,
                    methods: s(&["b"]),
                    events: vec![],
                },
            ),
        ]);
        let n = normalize(&ns);
        assert_eq!(n.len(), 1);
        let e = &n["eip155"];
        let mut chains = e.chains.clone().unwrap();
        chains.sort();
        assert_eq!(chains, s(&["eip155:1", "eip155:10"]));
        let mut methods = e.methods.clone();
        methods.sort();
        assert_eq!(methods, s(&["a", "b"]));

        let merged = merge_required_and_optional(&eip155_required(), &ns);
        assert_eq!(merged.len(), 1);
        assert!(
            merged["eip155"]
                .methods
                .contains(&"personal_sign".to_owned())
        );
        assert!(merged["eip155"].methods.contains(&"b".to_owned()));
    }

    #[test]
    fn build_approved() {
        let supported = BTreeMap::from([(
            "eip155".to_owned(),
            SupportedNamespace {
                chains: s(&["eip155:1", "eip155:10", "eip155:137"]),
                methods: s(&[
                    "personal_sign",
                    "eth_sendTransaction",
                    "eth_signTypedData_v4",
                ]),
                events: s(&["accountsChanged", "chainChanged"]),
                accounts: s(&["eip155:1:0xabc", "eip155:10:0xabc", "eip155:137:0xabc"]),
            },
        )]);
        let optional: ProposalNamespaces = BTreeMap::from([(
            "eip155".to_owned(),
            ProposalNamespace::new(
                ["eip155:10", "eip155:42161"],
                ["eth_sendTransaction", "wallet_foo"],
                ["chainChanged"],
            ),
        )]);
        let approved =
            build_approved_namespaces(&eip155_required(), &optional, &supported).unwrap();
        let ns = &approved["eip155"];
        assert_eq!(ns.chains.clone().unwrap(), s(&["eip155:1", "eip155:10"]));
        assert_eq!(ns.accounts, s(&["eip155:1:0xabc", "eip155:10:0xabc"]));
        assert_eq!(ns.methods, s(&["personal_sign", "eth_sendTransaction"]));
        assert_eq!(ns.events, s(&["accountsChanged", "chainChanged"]));
        assert!(ensure_conforming(&eip155_required(), &approved, "t").is_ok());

        // Nothing requested: everything supported is granted.
        assert_eq!(
            build_approved_namespaces(&BTreeMap::new(), &BTreeMap::new(), &supported).unwrap()["eip155"].accounts.len(),
            3
        );

        // Required chain not supported.
        let req: ProposalNamespaces = BTreeMap::from([(
            "eip155".to_owned(),
            ProposalNamespace::new(["eip155:5"], [], []),
        )]);
        assert!(build_approved_namespaces(&req, &BTreeMap::new(), &supported).is_err());

        // Optional-only namespace the wallet doesn't support is dropped.
        let opt_sol: ProposalNamespaces = BTreeMap::from([(
            "solana".to_owned(),
            ProposalNamespace::new(["solana:1"], [], []),
        )]);
        let approved = build_approved_namespaces(&BTreeMap::new(), &opt_sol, &supported).unwrap();
        assert!(approved.is_empty());
    }
}
