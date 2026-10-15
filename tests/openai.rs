mod support;

use erisagentauth::openai::{Method, OpenAiAccount};
use erisagentauth::{Event, Provider, SignInMethod, Status};
use serde_json::json;
use std::time::Duration;
use support::*;
use tokio::sync::broadcast;

fn account(file: &AccountFile, base: &str, port: u16) -> (OpenAiAccount, broadcast::Receiver<Event>) {
    let (events, receiver) = broadcast::channel(64);
    (OpenAiAccount::load_with_callback_port(file.path.clone(), base, APP, events, port).unwrap(), receiver)
}

/// An account file holding a login that is about to expire.
fn expiring(file: &AccountFile) {
    let stored = json!({"version": 1, "credential": {
        "access": chatgpt_token(30), "refresh": "refresh-old", "expires": now() + 30_000,
        "accountId": "account-1", "email": null, "plan": null,
    }});
    std::fs::write(&file.path, stored.to_string()).unwrap();
}

#[tokio::test]
async fn a_device_code_sign_in_saves_a_login_only_the_user_can_read() {
    let (base, counts, _server) = openai_server().await;
    let file = AccountFile::new();
    let (account, mut events) = account(&file, &base, free_port());
    assert_eq!(account.snapshot().status, Status::SignedOut);
    assert_eq!(account.snapshot().sign_in_methods, vec![SignInMethod::Browser, SignInMethod::DeviceCode]);

    let start = account.login(Method::DeviceCode).await.unwrap();
    assert_eq!(start.user_code.as_deref(), Some("ABCD-1234"));
    assert_eq!(start.url, format!("{base}/codex/device"));
    let pending = account.snapshot();
    assert_eq!(pending.status, Status::LoginPending);
    assert_eq!(pending.login, Some(start));

    assert_eq!(completion(&mut events).await, (Provider::OpenAi, true, None));
    assert_eq!(Counts::get(&counts.polls), 2, "the first poll was still pending");
    let signed_in = account.snapshot();
    assert_eq!(signed_in.status, Status::Connected);
    assert_eq!(signed_in.email.as_deref(), Some("person@example.test"));
    assert_eq!(signed_in.plan.as_deref(), Some("pro"));
    assert_eq!(signed_in.login, None);
    assert_eq!(file.mode(), 0o600);

    // Another process reading the same file is signed in as the same account.
    let (again, _) = self::account(&file, &base, free_port());
    let credential = again.current().await.unwrap();
    assert_eq!((credential.account_id.as_str(), credential.refresh.as_str()), ("account-1", "refresh-rotated"));
    assert_eq!(Counts::get(&counts.tokens), 1, "a fresh login needs no refresh");
}

#[tokio::test]
async fn a_browser_sign_in_takes_only_the_callback_it_started() {
    let (base, counts, _server) = openai_server().await;
    let file = AccountFile::new();
    let port = free_port();
    let (account, mut events) = account(&file, &base, port);
    let start = account.login(Method::Browser).await.unwrap();
    assert_eq!(start.user_code, None);
    let url = url::Url::parse(&start.url).unwrap();
    let query = |key: &str| url.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned());
    assert_eq!(url.path(), "/oauth/authorize");
    assert_eq!(query("originator").as_deref(), Some("testapp"));
    assert_eq!(query("redirect_uri"), Some(format!("http://localhost:{port}/auth/callback")));
    assert_eq!(query("code_challenge_method").as_deref(), Some("S256"));
    let state = query("state").unwrap();

    let client = reqwest::Client::new();
    let callback =
        |state: String| client.get(format!("http://127.0.0.1:{port}/auth/callback?state={state}&code=code-1")).send();
    let wrong = callback("someone-else".into()).await.unwrap();
    assert_eq!(wrong.status().as_u16(), 400);
    assert!(wrong.text().await.unwrap().contains("TestApp"));
    assert_eq!(Counts::get(&counts.tokens), 0);

    let right = callback(state).await.unwrap();
    assert_eq!(right.status().as_u16(), 200);
    assert_eq!(right.text().await.unwrap(), "Signed in to TestApp. You can close this window.");
    assert_eq!(completion(&mut events).await, (Provider::OpenAi, true, None));
    assert_eq!(account.snapshot().status, Status::Connected);
    assert_eq!(Counts::get(&counts.tokens), 1);
}

#[tokio::test]
async fn a_new_sign_in_replaces_a_pending_one_and_cancelling_frees_the_callback() {
    let (base, _counts, _server) = openai_server().await;
    let file = AccountFile::new();
    let port = free_port();
    let (account, _events) = account(&file, &base, port);
    let first = account.login(Method::Browser).await.unwrap();
    let second = account.login(Method::Browser).await.unwrap();
    assert_ne!(first.url, second.url);
    assert_eq!(account.snapshot().login, Some(second));
    account.cancel().await;
    assert_eq!(account.snapshot().status, Status::SignedOut);
    for _ in 0..100 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("a cancelled sign-in kept its callback port");
}

#[tokio::test]
async fn concurrent_callers_share_one_refresh() {
    let (base, counts, _server) = openai_server().await;
    let file = AccountFile::new();
    expiring(&file);
    let (account, _events) = account(&file, &base, free_port());
    let results = futures_util::future::join_all((0..8).map(|_| account.current())).await;
    assert_eq!(Counts::get(&counts.refreshes), 1);
    for result in results {
        assert_eq!(result.unwrap().refresh, "refresh-rotated");
    }
    assert_eq!(file.json()["credential"]["refresh"], "refresh-rotated");
    assert_eq!(file.mode(), 0o600);
}

#[tokio::test]
async fn a_refused_refresh_shows_an_error_until_the_next_sign_in() {
    let (base, counts, _server) = openai_server().await;
    counts.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    let file = AccountFile::new();
    expiring(&file);
    let (account, mut events) = account(&file, &base, free_port());
    let error = account.current().await.unwrap_err().to_string();
    assert!(error.to_lowercase().contains("sign in again"), "{error}");
    let snapshot = account.snapshot();
    assert_eq!(snapshot.status, Status::Error);
    assert_eq!(snapshot.detail.as_deref(), Some(error.as_str()));
    assert!(account.current().await.is_err());
    assert_eq!(Counts::get(&counts.refreshes), 1, "a refused login is not retried");

    counts.refuse.store(false, std::sync::atomic::Ordering::SeqCst);
    account.login(Method::DeviceCode).await.unwrap();
    assert!(completion(&mut events).await.1);
    assert_eq!(account.snapshot().status, Status::Connected);
    assert_eq!(account.snapshot().detail, None);
    account.current().await.unwrap();

    account.logout().await.unwrap();
    assert_eq!(account.snapshot().status, Status::SignedOut);
    assert!(account.current().await.is_err());
    assert!(!file.path.exists());
}

#[tokio::test]
async fn every_change_is_announced() {
    let (base, _counts, _server) = openai_server().await;
    let file = AccountFile::new();
    let (account, mut events) = account(&file, &base, free_port());
    account.login(Method::DeviceCode).await.unwrap();
    let mut statuses = Vec::new();
    while let Event::Account(snapshot) =
        tokio::time::timeout(Duration::from_secs(10), events.recv()).await.unwrap().unwrap()
    {
        assert_eq!(snapshot.provider_id, Provider::OpenAi);
        statuses.push(snapshot.status);
    }
    assert_eq!(statuses, vec![Status::LoginPending, Status::Connected]);
}

#[tokio::test]
async fn an_unreadable_account_file_is_an_error() {
    let file = AccountFile::new();
    std::fs::write(&file.path, "{\"version\": 7}").unwrap();
    let (events, _) = broadcast::channel(4);
    assert!(OpenAiAccount::load(file.path.clone(), "http://127.0.0.1:1", APP, events).is_err());
}

#[cfg(feature = "harness")]
#[tokio::test]
async fn requests_carry_the_login_and_its_account() {
    use erisharness::provider::Credentials;
    let (base, _counts, _server) = openai_server().await;
    let file = AccountFile::new();
    expiring(&file);
    let (account, _events) = account(&file, &base, free_port());
    let authorization = account.authorize().await.unwrap();
    assert_eq!(authorization.token, account.current().await.unwrap().access);
    assert_eq!(authorization.headers, vec![("chatgpt-account-id".to_owned(), "account-1".to_owned())]);
}
