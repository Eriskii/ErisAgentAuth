//! Stand-ins for OpenAI's and Anthropic's auth servers, served on local ports, and a place for
//! each test's account file.
#![allow(dead_code)]

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use erisagentauth::{App, Event, Provider};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::broadcast;

pub const APP: App = App { name: "TestApp", originator: "testapp" };

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Aborts the server when dropped.
pub struct Served(tokio::task::AbortHandle);

impl Drop for Served {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn serve(router: Router) -> (String, Served) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (base, Served(task.abort_handle()))
}

/// A port nothing listens on, for a sign-in's callback.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A fresh directory's `account.json`; the directory goes when the guard drops.
pub struct AccountFile {
    pub path: PathBuf,
}

impl AccountFile {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("erisagentauth-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Self { path: dir.join("account.json") }
    }

    pub fn mode(&self) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&self.path).unwrap().permissions().mode() & 0o777
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&std::fs::read(&self.path).unwrap()).unwrap()
    }
}

impl Drop for AccountFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
    }
}

/// What a stand-in server has seen, and whether it turns refreshes down.
#[derive(Default)]
pub struct Counts {
    pub tokens: AtomicUsize,
    pub refreshes: AtomicUsize,
    pub polls: AtomicUsize,
    pub profiles: AtomicUsize,
    pub refuse: AtomicBool,
}

impl Counts {
    pub fn get(counter: &AtomicUsize) -> usize {
        counter.load(Ordering::SeqCst)
    }
}

/// A ChatGPT access token: a JWT whose claims name the account, email and plan.
pub fn chatgpt_token(seconds: u64) -> String {
    let claims = json!({
        "exp": now() / 1000 + seconds,
        "email": "person@example.test",
        "https://api.openai.com/auth": {"chatgpt_account_id": "account-1", "chatgpt_plan_type": "pro"},
    });
    format!("e30.{}.signature", URL_SAFE_NO_PAD.encode(claims.to_string()))
}

/// OpenAI's auth server. The device code is pending on the first poll and granted on the
/// next.
pub async fn openai_server() -> (String, Arc<Counts>, Served) {
    let counts = Arc::new(Counts::default());
    let router = Router::new()
        .route("/oauth/token", post(openai_token))
        .route(
            "/api/accounts/deviceauth/usercode",
            post(|| async { Json(json!({"device_auth_id": "device-1", "user_code": "ABCD-1234", "interval": "1"})) }),
        )
        .route("/api/accounts/deviceauth/token", post(openai_poll))
        .with_state(counts.clone());
    let (base, served) = serve(router).await;
    (base, counts, served)
}

async fn openai_token(State(counts): State<Arc<Counts>>, body: String) -> (StatusCode, Json<Value>) {
    counts.tokens.fetch_add(1, Ordering::SeqCst);
    let refreshing = body.contains("refresh_token\"");
    if refreshing {
        counts.refreshes.fetch_add(1, Ordering::SeqCst);
        if counts.refuse.load(Ordering::SeqCst) {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_grant"})));
        }
        // Holding the refresh a moment lets concurrent callers pile up behind it.
        tokio::time::sleep(Duration::from_millis(100)).await;
    } else {
        assert!(body.contains("grant_type=authorization_code"), "{body}");
    }
    (
        StatusCode::OK,
        Json(json!({"access_token": chatgpt_token(3600), "refresh_token": "refresh-rotated", "expires_in": 3600})),
    )
}

async fn openai_poll(State(counts): State<Arc<Counts>>) -> (StatusCode, Json<Value>) {
    if counts.polls.fetch_add(1, Ordering::SeqCst) == 0 {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "deviceauth_authorization_pending"})));
    }
    (StatusCode::OK, Json(json!({"authorization_code": "code-1", "code_verifier": "verifier-1"})))
}

/// Anthropic's API (the login's profile) and auth server (refreshes) in one.
pub async fn claude_server() -> (String, Arc<Counts>, Served) {
    let counts = Arc::new(Counts::default());
    let router = Router::new()
        .route("/v1/oauth/token", post(claude_token))
        .route("/api/oauth/profile", get(claude_profile))
        .with_state(counts.clone());
    let (base, served) = serve(router).await;
    (base, counts, served)
}

async fn claude_token(State(counts): State<Arc<Counts>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    counts.refreshes.fetch_add(1, Ordering::SeqCst);
    assert_eq!(body["grant_type"], "refresh_token");
    assert_eq!(body["client_id"], "9d1c250a-e61b-44d9-88ed-5944d1962f5e");
    if counts.refuse.load(Ordering::SeqCst) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"})));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let n = Counts::get(&counts.refreshes);
    (
        StatusCode::OK,
        Json(json!({
            "access_token": format!("claude-access-{n}"), "refresh_token": format!("claude-refresh-{n}"),
            "expires_in": 3600, "account": {"uuid": "claude-account", "email_address": "person@example.test"},
        })),
    )
}

async fn claude_profile(
    State(counts): State<Arc<Counts>>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, Json<Value>) {
    counts.profiles.fetch_add(1, Ordering::SeqCst);
    let authorized =
        headers.get("authorization").and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("Bearer "));
    let beta = headers.get("anthropic-beta").and_then(|v| v.to_str().ok()) == Some("oauth-2025-04-20");
    if !authorized || !beta || counts.refuse.load(Ordering::SeqCst) {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    (
        StatusCode::OK,
        Json(json!({
            "account": {"uuid": "claude-account", "email": "person@example.test"},
            "organization": {"organization_type": "claude_max"},
        })),
    )
}

/// The next sign-in outcome on `events`.
pub async fn completion(events: &mut broadcast::Receiver<Event>) -> (Provider, bool, Option<String>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Event::LoginCompleted { provider, ok, error } = events.recv().await.unwrap() {
                return (provider, ok, error);
            }
        }
    })
    .await
    .expect("a sign-in outcome")
}
