//! Telegram session storage.
//!
//! The session string is a bearer credential: anyone holding it can act as the
//! signed-in Telegram account. On desktop it is kept in the operating system's
//! credential store (Windows Credential Manager, macOS Keychain, Secret Service
//! on Linux), never in a plain file. `teledrive_session.json` keeps only the
//! phone number, which is not a credential and is needed to find the
//! per-account storage channel after logout.
//!
//! Legacy installs stored the session in that JSON file (and a copy under the
//! `telegram_session` key of the vault file). Loading migrates it into the
//! credential store and scrubs both plain copies. If the credential store is
//! unavailable, the session is kept in memory for the current run only and the
//! user signs in again next time; it is never written back in plain text.
//!
//! On Android and iOS the session stays in the app-private data directory,
//! which the OS sandbox already restricts to the app.

use serde_json::{json, Map, Value};

/// Legacy vault key that held a second plain-text copy of the session.
pub const LEGACY_VAULT_SESSION_KEY: &str = "telegram_session";

/// Where the session secret lives.
pub trait SecretStore {
    fn get(&self) -> Result<Option<String>, String>;
    fn set(&self, secret: &str) -> Result<(), String>;
    fn delete(&self) -> Result<(), String>;
}

/// Desktop credential store backed by the `keyring` crate.
#[cfg(desktop)]
pub struct OsKeyring;

#[cfg(desktop)]
impl OsKeyring {
    const SERVICE: &'static str = "com.teledrive.app";
    const ACCOUNT: &'static str = "telegram_session";

    fn entry() -> Result<keyring::Entry, String> {
        keyring::Entry::new(Self::SERVICE, Self::ACCOUNT)
            .map_err(|e| format!("credential store unavailable: {e}"))
    }
}

#[cfg(desktop)]
impl SecretStore for OsKeyring {
    fn get(&self) -> Result<Option<String>, String> {
        match Self::entry()?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("credential store read failed: {e}")),
        }
    }

    fn set(&self, secret: &str) -> Result<(), String> {
        Self::entry()?
            .set_password(secret)
            .map_err(|e| format!("credential store write failed: {e}"))
    }

    fn delete(&self) -> Result<(), String> {
        match Self::entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("credential store delete failed: {e}")),
        }
    }
}

/// Parses the session file. A missing or unreadable file means "no session".
pub fn parse_session_file(contents: Option<&str>) -> Map<String, Value> {
    contents
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

/// File body that carries no secret.
pub fn metadata_body(phone: Option<&str>) -> String {
    json!({ "session": Value::Null, "phone": phone }).to_string()
}

fn non_empty(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Result of loading: what to return to the UI and how to rewrite the file.
#[derive(Debug, PartialEq)]
pub struct LoadOutcome {
    pub session: Option<String>,
    pub phone: Option<String>,
    /// New file body when the file still contained a plain-text session.
    pub rewrite_file: Option<String>,
}

/// Loads the session, migrating a legacy plain-text copy into `store`.
///
/// The plain copy is always scrubbed from the file. When the migration cannot
/// be confirmed (write or read-back fails, or the value read back differs),
/// the legacy session is still returned for this run only.
pub fn load(store: &dyn SecretStore, file: &Map<String, Value>) -> LoadOutcome {
    let phone = non_empty(file.get("phone"));
    if let Some(legacy) = non_empty(file.get("session")) {
        let confirmed = store.set(&legacy).is_ok()
            && matches!(store.get(), Ok(Some(ref stored)) if *stored == legacy);
        if !confirmed {
            // Do not leave a half-written or mismatched secret behind.
            let _ = store.delete();
        }
        return LoadOutcome {
            session: Some(legacy),
            phone: phone.clone(),
            rewrite_file: Some(metadata_body(phone.as_deref())),
        };
    }
    LoadOutcome {
        session: store.get().ok().flatten(),
        phone,
        rewrite_file: None,
    }
}

/// Stores a new session. The caller writes `metadata_body(phone)` to the file
/// only after this succeeds; on failure nothing is persisted.
pub fn save(store: &dyn SecretStore, session: &str) -> Result<(), String> {
    store.set(session)
}

/// Removes the legacy `telegram_session` key from a parsed vault map.
/// Returns true when the map changed.
pub fn scrub_vault(vault: &mut Map<String, Value>) -> bool {
    vault.remove(LEGACY_VAULT_SESSION_KEY).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct MemoryStore {
        value: RefCell<Option<String>>,
        fail_set: bool,
        corrupt_reads: bool,
    }

    impl SecretStore for MemoryStore {
        fn get(&self) -> Result<Option<String>, String> {
            if self.corrupt_reads {
                return Ok(Some("something else".into()));
            }
            Ok(self.value.borrow().clone())
        }
        fn set(&self, secret: &str) -> Result<(), String> {
            if self.fail_set {
                return Err("locked".into());
            }
            *self.value.borrow_mut() = Some(secret.to_owned());
            Ok(())
        }
        fn delete(&self) -> Result<(), String> {
            *self.value.borrow_mut() = None;
            Ok(())
        }
    }

    fn file(body: &str) -> Map<String, Value> {
        parse_session_file(Some(body))
    }

    #[test]
    fn migrates_legacy_plain_session_and_scrubs_file() {
        let store = MemoryStore::default();
        let out = load(&store, &file(r#"{"session":"SECRET","phone":"+1"}"#));

        assert_eq!(out.session.as_deref(), Some("SECRET"));
        assert_eq!(out.phone.as_deref(), Some("+1"));
        assert_eq!(store.value.borrow().as_deref(), Some("SECRET"));
        let rewritten = out.rewrite_file.expect("file must be rewritten");
        assert!(!rewritten.contains("SECRET"));
        assert!(rewritten.contains("+1"));
    }

    #[test]
    fn failed_migration_keeps_session_in_memory_only() {
        let store = MemoryStore {
            fail_set: true,
            ..Default::default()
        };
        let out = load(&store, &file(r#"{"session":"SECRET","phone":"+1"}"#));

        assert_eq!(out.session.as_deref(), Some("SECRET"));
        assert!(store.value.borrow().is_none());
        assert!(!out.rewrite_file.unwrap().contains("SECRET"));
    }

    #[test]
    fn unconfirmed_migration_removes_the_stored_copy() {
        let store = MemoryStore {
            corrupt_reads: true,
            ..Default::default()
        };
        let out = load(&store, &file(r#"{"session":"SECRET"}"#));

        assert_eq!(out.session.as_deref(), Some("SECRET"));
        assert!(store.value.borrow().is_none());
    }

    #[test]
    fn loads_from_store_when_file_has_no_secret() {
        let store = MemoryStore::default();
        store.set("STORED").unwrap();
        let out = load(&store, &file(&metadata_body(Some("+1"))));

        assert_eq!(out.session.as_deref(), Some("STORED"));
        assert_eq!(out.phone.as_deref(), Some("+1"));
        assert_eq!(out.rewrite_file, None);
    }

    #[test]
    fn missing_or_corrupt_file_means_no_session() {
        let store = MemoryStore::default();
        assert_eq!(load(&store, &parse_session_file(None)).session, None);
        assert_eq!(load(&store, &file("not json")).session, None);
    }

    #[test]
    fn save_failure_reports_error_so_nothing_is_written() {
        let store = MemoryStore {
            fail_set: true,
            ..Default::default()
        };
        assert!(save(&store, "SECRET").is_err());
        assert!(store.value.borrow().is_none());
    }

    #[test]
    fn metadata_body_never_contains_a_session() {
        let body: Value = serde_json::from_str(&metadata_body(Some("+1"))).unwrap();
        assert!(body["session"].is_null());
        assert_eq!(body["phone"], "+1");
    }

    #[test]
    fn scrubs_legacy_vault_copy() {
        let mut vault = file(r#"{"telegram_session":"SECRET","telegram_api_id":"1"}"#);
        assert!(scrub_vault(&mut vault));
        assert!(!vault.contains_key(LEGACY_VAULT_SESSION_KEY));
        assert!(vault.contains_key("telegram_api_id"));
        assert!(!scrub_vault(&mut vault));
    }
}
