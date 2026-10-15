mod support;

use erisagentauth::claude::{ClaudeAccount, ClaudeLogin};
use erisagentauth::{Event, Provider, SignInMethod, Status};
use serde_json::json;
use std::sync::atomic::Ordering;
use support::*;
use tokio::sync::broadcast;

fn account(file: &AccountFile, base: &str) -> (ClaudeAccount, broadcast::Receiver<Event>) {
    let (events, receiver) = broadcast::channel(64);
    (ClaudeAccount::load(file.path.clone(), base, base, events).unwrap(), receiver)
}

/// A Claude Code credentials file whose login expires `expires_in` ms from now.
fn credentials(expires_in: i64) -> String {
    json!({"claudeAiOauth": {
        "accessToken": "claude-access-0", "refreshToken": "claude-refresh-0",
        "expiresAt": (now() as i64 + expires_in), "scopes": ["user:inference", "user:profile"],
        "subscriptionType": "pro",
    }})
    .to_string()
}

#[tokio::test]
async fn a_credentials_file_signs_in_once_anthropic_accepts_it() {
    let (base, counts, _server) = claude_server().await;
    let file = AccountFile::new();
    let (account, mut events) = account(&file, &base);
    let methods = account.snapshot().sign_in_methods;
    assert_eq!(methods[0], SignInMethod::CredentialsFile);
    assert_eq!(methods.contains(&SignInMethod::Keychain), cfg!(target_os = "macos"));

    let snapshot = account.import(&credentials(3_600_000)).await.unwrap();
    assert_eq!(snapshot.provider_id, Provider::Anthropic);
    assert_eq!(snapshot.status, Status::Connected);
    assert_eq!(snapshot.email.as_deref(), Some("person@example.test"));
    assert_eq!(snapshot.plan.as_deref(), Some("pro"), "the file's subscription wins over the organization's");
    assert_eq!(Counts::get(&counts.profiles), 1);
    assert_eq!(Counts::get(&counts.refreshes), 0);
    assert!(matches!(events.recv().await.unwrap(), Event::Account(s) if s.status == Status::Connected));
    assert_eq!(file.mode(), 0o600);

    let login = account.current().await.unwrap();
    assert_eq!(login.account_id.as_deref(), Some("claude-account"));
    let install = account.install_id().to_owned();
    assert!(!install.is_empty());
    let (again, _) = self::account(&file, &base);
    assert_eq!(again.install_id(), install, "the install id outlives the process");
    assert_eq!(again.current().await.unwrap(), login);
}

#[tokio::test]
async fn an_expiring_file_is_refreshed_before_it_is_kept() {
    let (base, counts, _server) = claude_server().await;
    let file = AccountFile::new();
    let (account, _events) = account(&file, &base);
    account.import(&credentials(10_000)).await.unwrap();
    assert_eq!(Counts::get(&counts.refreshes), 1);
    let login = account.current().await.unwrap();
    assert_eq!((login.access.as_str(), login.refresh.as_deref()), ("claude-access-1", Some("claude-refresh-1")));
}

#[tokio::test]
async fn concurrent_callers_share_one_refresh_of_a_single_use_token() {
    let (base, counts, _server) = claude_server().await;
    let file = AccountFile::new();
    let (account, _events) = account(&file, &base);
    account.import(&credentials(3_600_000)).await.unwrap();
    // The stored login nears its end.
    let mut stored = file.json();
    stored["login"]["expires"] = json!(now() + 1_000);
    std::fs::write(&file.path, stored.to_string()).unwrap();
    let (account, _events) = self::account(&file, &base);

    let results = futures_util::future::join_all((0..8).map(|_| account.current())).await;
    assert_eq!(Counts::get(&counts.refreshes), 1);
    for result in results {
        assert_eq!(result.unwrap().refresh.as_deref(), Some("claude-refresh-1"));
    }
    assert_eq!(file.json()["login"]["refresh"], "claude-refresh-1");
}

#[tokio::test]
async fn a_refused_refresh_needs_a_new_login() {
    let (base, counts, _server) = claude_server().await;
    let file = AccountFile::new();
    let (account, _events) = account(&file, &base);
    account.import(&credentials(3_600_000)).await.unwrap();
    let mut stored = file.json();
    stored["login"]["expires"] = json!(now());
    std::fs::write(&file.path, stored.to_string()).unwrap();
    let (account, _events) = self::account(&file, &base);

    counts.refuse.store(true, Ordering::SeqCst);
    let error = account.current().await.unwrap_err().to_string();
    assert!(error.contains("no longer accepts"), "{error}");
    assert_eq!(account.snapshot().status, Status::Error);
    assert_eq!(account.snapshot().detail.as_deref(), Some(error.as_str()));
    assert!(account.current().await.is_err());
    assert_eq!(Counts::get(&counts.refreshes), 1);

    counts.refuse.store(false, Ordering::SeqCst);
    account.import(&credentials(3_600_000)).await.unwrap();
    assert_eq!(account.snapshot().status, Status::Connected);
    assert_eq!(account.snapshot().detail, None);
    account.logout().await.unwrap();
    assert_eq!(account.snapshot().status, Status::SignedOut);
    assert!(account.current().await.is_err());
    assert!(file.json()["installId"].is_string(), "signing out keeps the install id");
}

#[tokio::test]
async fn a_login_anthropic_refuses_is_not_kept() {
    let (base, counts, _server) = claude_server().await;
    counts.refuse.store(true, Ordering::SeqCst);
    let file = AccountFile::new();
    let (account, _events) = account(&file, &base);
    assert!(account.import(&credentials(3_600_000)).await.is_err());
    assert_eq!(account.snapshot().status, Status::SignedOut);
}

#[test]
fn only_claude_code_logins_that_can_make_model_calls_parse() {
    let login = ClaudeLogin::parse(&credentials(5)).unwrap();
    assert_eq!(
        (login.access.as_str(), login.refresh.as_deref(), login.plan.as_deref()),
        ("claude-access-0", Some("claude-refresh-0"), Some("pro"))
    );
    let token_only = ClaudeLogin::parse(&json!({"claudeAiOauth": {"accessToken": "a"}}).to_string()).unwrap();
    assert_eq!((token_only.refresh, token_only.expires), (None, None));
    for other in ["{}", "[]", "\"text\"", "not json", r#"{"claudeAiOauth": {"accessToken": ""}}"#] {
        assert!(ClaudeLogin::parse(other).is_err(), "{other}");
    }
    let scopeless = json!({"claudeAiOauth": {"accessToken": "a", "scopes": ["user:profile"]}}).to_string();
    assert!(ClaudeLogin::parse(&scopeless).unwrap_err().to_string().contains("user:inference"));
}

#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn only_macos_has_a_keychain_login() {
    let file = AccountFile::new();
    let (account, _events) = account(&file, "http://127.0.0.1:1");
    assert!(account.import_keychain().await.unwrap_err().to_string().contains("macOS"));
}

#[cfg(feature = "harness")]
#[tokio::test]
async fn requests_carry_the_login_as_claude_code_does() {
    use erisharness::provider::Credentials;
    let (base, _counts, _server) = claude_server().await;
    let file = AccountFile::new();
    let (account, _events) = account(&file, &base);
    account.import(&credentials(3_600_000)).await.unwrap();
    let authorization = account.authorize().await.unwrap();
    assert_eq!(authorization.token, "claude-access-0");
    let identity = account.claude_code().await;
    assert_eq!(identity.install_id, account.install_id());
    assert_eq!(identity.account_id.as_deref(), Some("claude-account"));
}

/// A Claude Code credentials file at its own path, holding `access` until `expires_in` ms from now.
fn write_credentials(path: &std::path::Path, access: &str, expires_in: i64) {
    let text = json!({"claudeAiOauth": {
        "accessToken": access, "refreshToken": "claude-code-refresh",
        "expiresAt": (now() as i64 + expires_in), "scopes": ["user:inference", "user:profile"],
        "subscriptionType": "max",
    }});
    std::fs::write(path, text.to_string()).unwrap();
}

#[tokio::test]
async fn a_bound_file_is_read_on_every_call_and_never_refreshed() {
    let (base, counts, _server) = claude_server().await;
    let file = AccountFile::new();
    let claude_code = file.path.with_file_name(".credentials.json");
    write_credentials(&claude_code, "from-claude-code-1", 3_600_000);
    let (account, mut events) = account(&file, &base);

    let snapshot = account.bind(&claude_code).await.unwrap();
    assert_eq!(snapshot.status, Status::Connected);
    assert_eq!(snapshot.email.as_deref(), Some("person@example.test"));
    assert_eq!(snapshot.plan.as_deref(), Some("max"));
    assert_eq!(snapshot.bound.as_deref(), Some(claude_code.as_path()));
    assert!(matches!(events.recv().await.unwrap(), Event::Account(s) if s.status == Status::Connected));
    assert!(file.json()["login"].is_null(), "no tokens are kept, only the path");
    assert_eq!(file.json()["bound"]["path"], claude_code.to_str().unwrap());

    let login = account.current().await.unwrap();
    assert_eq!(login.access, "from-claude-code-1");
    assert_eq!(login.account_id.as_deref(), Some("claude-account"));

    // Claude Code refreshes its own file; the account takes the new token as it is.
    write_credentials(&claude_code, "from-claude-code-2", 3_600_000);
    assert_eq!(account.current().await.unwrap().access, "from-claude-code-2");
    // A token close to its end is still Claude Code's to refresh.
    write_credentials(&claude_code, "from-claude-code-3", 30_000);
    assert_eq!(account.current().await.unwrap().access, "from-claude-code-3");
    assert_eq!(Counts::get(&counts.refreshes), 0, "a bound file is never refreshed");
}

#[tokio::test]
async fn an_expired_bound_file_is_an_error_until_claude_code_refreshes_it() {
    let (base, counts, _server) = claude_server().await;
    let file = AccountFile::new();
    let claude_code = file.path.with_file_name(".credentials.json");
    write_credentials(&claude_code, "fresh", 3_600_000);
    let (account, _events) = account(&file, &base);
    account.bind(&claude_code).await.unwrap();

    write_credentials(&claude_code, "stale", -1_000);
    let error = account.current().await.unwrap_err().to_string();
    assert!(error.contains("has expired") && error.contains(claude_code.to_str().unwrap()), "{error}");
    assert_eq!(account.snapshot().status, Status::Error);
    assert_eq!(account.snapshot().detail.as_deref(), Some(error.as_str()));

    std::fs::remove_file(&claude_code).unwrap();
    assert!(account.current().await.is_err(), "a missing file is an error too");

    write_credentials(&claude_code, "refreshed", 3_600_000);
    assert_eq!(account.current().await.unwrap().access, "refreshed");
    assert_eq!(account.snapshot().status, Status::Connected);
    assert_eq!(account.snapshot().detail, None);
    assert_eq!(Counts::get(&counts.refreshes), 0);
}

#[tokio::test]
async fn a_binding_lasts_across_runs_until_another_sign_in_replaces_it() {
    let (base, counts, _server) = claude_server().await;
    let file = AccountFile::new();
    let claude_code = file.path.with_file_name(".credentials.json");
    write_credentials(&claude_code, "bound-token", 3_600_000);
    let (account, _events) = account(&file, &base);
    account.bind(&claude_code).await.unwrap();

    let (again, _events) = self::account(&file, &base);
    assert!(again.signed_in().await);
    assert_eq!(again.snapshot().bound.as_deref(), Some(claude_code.as_path()));
    assert_eq!(again.current().await.unwrap().access, "bound-token");

    again.import(&credentials(3_600_000)).await.unwrap();
    assert_eq!(again.snapshot().bound, None);
    assert!(file.json()["bound"].is_null());
    assert_eq!(again.current().await.unwrap().access, "claude-access-0", "the import replaced the binding");

    again.bind(&claude_code).await.unwrap();
    again.logout().await.unwrap();
    assert!(!again.signed_in().await);
    assert!(again.current().await.is_err());
    assert_eq!(Counts::get(&counts.refreshes), 0);
}

#[tokio::test]
async fn binding_refuses_a_file_that_cannot_sign_in() {
    let (base, counts, _server) = claude_server().await;
    let file = AccountFile::new();
    let claude_code = file.path.with_file_name(".credentials.json");
    let (account, _events) = account(&file, &base);

    assert!(account.bind(&claude_code).await.is_err(), "no file");
    std::fs::write(&claude_code, "{}").unwrap();
    assert!(account.bind(&claude_code).await.is_err(), "not a login");
    write_credentials(&claude_code, "stale", -1_000);
    assert!(account.bind(&claude_code).await.unwrap_err().to_string().contains("has expired"));
    write_credentials(&claude_code, "fresh", 3_600_000);
    counts.refuse.store(true, Ordering::SeqCst);
    assert!(account.bind(&claude_code).await.is_err(), "Anthropic refuses it");
    assert_eq!(account.snapshot().status, Status::SignedOut);
    assert!(file.json()["bound"].is_null());
}
