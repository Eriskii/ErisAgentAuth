//! The ChatGPT account, signed in as the Codex CLI signs in: OAuth with PKCE through the
//! browser, back to a callback on this machine, or a device code entered on any device.
use crate::storage::{read_json, remove, write_json};
use crate::{AccountSnapshot, App, Event, LoginStart, Provider, REFRESH_MARGIN_MS, SignInMethod, Status, now};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, broadcast};

/// Where ChatGPT logins are made and refreshed.
pub const AUTH: &str = "https://auth.openai.com";
/// Where a ChatGPT login reaches the Codex models.
pub const CODEX_API: &str = "https://chatgpt.com/backend-api/codex";
/// The Codex CLI's OAuth client, which ChatGPT logins sign in and refresh through.
const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
/// The callback port the Codex client is registered with.
pub const CALLBACK_PORT: u16 = 1455;
/// How long a sign-in may wait for the browser or the device code.
const SIGN_IN_FOR: Duration = Duration::from_secs(900);

/// A ChatGPT login.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    pub access: String,
    pub refresh: String,
    /// Unix milliseconds.
    pub expires: u64,
    /// The ChatGPT account, which requests name in `chatgpt-account-id`.
    pub account_id: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
}

/// How to sign in with ChatGPT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Browser,
    DeviceCode,
}

impl FromStr for Method {
    type Err = anyhow::Error;

    /// `browser` or `device-code`, as [`SignInMethod`] names them.
    fn from_str(name: &str) -> Result<Self> {
        match name {
            "browser" => Ok(Self::Browser),
            "device-code" => Ok(Self::DeviceCode),
            _ => bail!("ChatGPT has no sign-in method {name}"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    credential: Option<Credential>,
}

#[derive(Default)]
struct State {
    credential: Option<Credential>,
    pending: Option<Pending>,
    /// Why the stored login no longer works; only a new sign-in helps.
    refused: Option<String>,
    /// Why the last sign-in failed.
    failed: Option<String>,
    stopped: bool,
    /// Numbers sign-ins, so one that was replaced cannot finish.
    attempts: u64,
}

struct Pending {
    attempt: u64,
    task: tokio::task::AbortHandle,
    start: LoginStart,
}

impl State {
    fn end_pending(&mut self) {
        if let Some(pending) = self.pending.take() {
            pending.task.abort();
        }
    }
}

#[derive(Clone)]
pub struct OpenAiAccount(Arc<Inner>);

struct Inner {
    path: PathBuf,
    /// The OpenAI auth server.
    base: String,
    app: App,
    callback_port: u16,
    client: reqwest::Client,
    events: broadcast::Sender<Event>,
    state: AsyncMutex<State>,
    snapshot: Mutex<AccountSnapshot>,
}

impl OpenAiAccount {
    /// The login stored at `path`, made and refreshed at the auth server at `auth_base`
    /// ([`AUTH`]), announcing its changes on `events`.
    pub fn load(path: PathBuf, auth_base: &str, app: App, events: broadcast::Sender<Event>) -> Result<Self> {
        Self::load_with_callback_port(path, auth_base, app, events, CALLBACK_PORT)
    }

    /// As [`load`](Self::load), with browser sign-ins returning to another local port. Only
    /// stand-in auth servers accept one other than [`CALLBACK_PORT`].
    pub fn load_with_callback_port(
        path: PathBuf,
        auth_base: &str,
        app: App,
        events: broadcast::Sender<Event>,
        callback_port: u16,
    ) -> Result<Self> {
        let credential = match read_json::<Stored>(&path)? {
            Some(stored) => {
                ensure!(stored.version == 1, "unsupported ChatGPT account version {}", stored.version);
                stored.credential
            }
            None => None,
        };
        if let Some(credential) = &credential {
            ensure!(
                !credential.access.is_empty() && !credential.refresh.is_empty() && !credential.account_id.is_empty(),
                "the stored ChatGPT login is incomplete"
            );
        }
        let state = State { credential, ..State::default() };
        Ok(Self(Arc::new(Inner {
            snapshot: Mutex::new(snapshot(&state)),
            path,
            base: auth_base.trim_end_matches('/').to_owned(),
            app,
            callback_port,
            client: crate::client(),
            events,
            state: AsyncMutex::new(state),
        })))
    }

    pub fn snapshot(&self) -> AccountSnapshot {
        self.0.snapshot.lock().unwrap().clone()
    }

    pub async fn signed_in(&self) -> bool {
        self.0.state.lock().await.credential.is_some()
    }

    fn changed(&self, state: &State) {
        let value = snapshot(state);
        *self.0.snapshot.lock().unwrap() = value.clone();
        let _ = self.0.events.send(Event::Account(value));
    }

    fn save(&self, state: &mut State, credential: Option<Credential>) -> Result<()> {
        match &credential {
            Some(credential) => write_json(&self.0.path, &Stored { version: 1, credential: Some(credential.clone()) })?,
            None => remove(&self.0.path)?,
        }
        state.credential = credential;
        Ok(())
    }

    /// The login, refreshed first when it is about to expire. Concurrent callers share one
    /// refresh.
    pub async fn current(&self) -> Result<Credential> {
        let mut state = self.0.state.lock().await;
        ensure!(!state.stopped, "the ChatGPT account is shut down");
        if let Some(refused) = &state.refused {
            bail!("{refused}");
        }
        let credential = state.credential.clone().ok_or_else(|| anyhow!("Sign in with ChatGPT to use its models."))?;
        if credential.expires > now() + REFRESH_MARGIN_MS {
            return Ok(credential);
        }
        let response = self
            .post("/oauth/token")
            .json(&json!({"grant_type": "refresh_token", "refresh_token": credential.refresh, "client_id": CLIENT_ID}))
            .send()
            .await
            .map_err(http_error)?;
        let status = response.status();
        if matches!(status.as_u16(), 400 | 401 | 403) {
            let refused =
                "ChatGPT no longer accepts this login: it was signed out or refreshed elsewhere. Sign in again.";
            state.refused = Some(refused.into());
            self.changed(&state);
            bail!("{refused}");
        }
        ensure!(status.is_success(), "refreshing the ChatGPT login failed ({status})");
        let refreshed = token_credential(response.json().await.map_err(http_error)?, &credential.refresh)?;
        self.save(&mut state, Some(refreshed.clone()))?;
        self.changed(&state);
        Ok(refreshed)
    }

    /// Starts signing in, replacing a sign-in already under way. The account's snapshot holds
    /// the returned start until an [`Event::LoginCompleted`] follows.
    pub async fn login(&self, method: Method) -> Result<LoginStart> {
        let mut state = self.0.state.lock().await;
        ensure!(!state.stopped, "the ChatGPT account is shut down");
        state.end_pending();
        state.failed = None;
        let flow = match method {
            Method::Browser => self.browser_flow().await,
            Method::DeviceCode => self.device_flow().await,
        };
        let flow = match flow {
            Ok(flow) => flow,
            Err(error) => {
                self.changed(&state);
                return Err(error);
            }
        };
        state.attempts += 1;
        let attempt = state.attempts;
        let account = self.clone();
        let task = tokio::spawn(async move {
            let result = match tokio::time::timeout(SIGN_IN_FOR, flow.completion).await {
                Ok(result) => result,
                Err(_) => Err(anyhow!("Signing in with ChatGPT timed out.")),
            };
            let mut state = account.0.state.lock().await;
            if state.stopped || state.pending.as_ref().map(|p| p.attempt) != Some(attempt) {
                return;
            }
            state.pending = None;
            let result = result.and_then(|credential| account.save(&mut state, Some(credential)));
            match &result {
                Ok(()) => state.refused = None,
                Err(error) => state.failed = Some(format!("{error:#}")),
            }
            account.changed(&state);
            let _ = account.0.events.send(Event::LoginCompleted {
                provider: Provider::OpenAi,
                ok: result.is_ok(),
                error: result.err().map(|e| format!("{e:#}")),
            });
        });
        let start = LoginStart { url: flow.url, user_code: flow.user_code };
        state.pending = Some(Pending { attempt, task: task.abort_handle(), start: start.clone() });
        self.changed(&state);
        Ok(start)
    }

    /// Ends the sign-in under way, if there is one.
    pub async fn cancel(&self) {
        let mut state = self.0.state.lock().await;
        state.end_pending();
        self.changed(&state);
    }

    pub async fn logout(&self) -> Result<()> {
        let mut state = self.0.state.lock().await;
        state.end_pending();
        self.save(&mut state, None)?;
        state.refused = None;
        state.failed = None;
        self.changed(&state);
        Ok(())
    }

    /// Ends any sign-in under way; afterwards the account gives out no login.
    pub async fn shutdown(&self) {
        let mut state = self.0.state.lock().await;
        state.stopped = true;
        state.end_pending();
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.0.client.post(format!("{}{path}", self.0.base))
    }

    async fn browser_flow(&self) -> Result<Flow> {
        let verifier =
            URL_SAFE_NO_PAD.encode([*uuid::Uuid::new_v4().as_bytes(), *uuid::Uuid::new_v4().as_bytes()].concat());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let nonce = uuid::Uuid::new_v4().to_string();
        let port = self.0.callback_port;
        let listener = listen(port).await?;
        let redirect = format!("http://localhost:{port}/auth/callback");
        let mut url = url::Url::parse(&format!("{}/oauth/authorize", self.0.base))?;
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", &redirect),
            ("scope", "openid profile email offline_access"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", &nonce),
            ("id_token_add_organizations", "true"),
            ("codex_cli_simplified_flow", "true"),
            ("originator", self.0.app.originator),
        ]);
        let account = self.clone();
        Ok(Flow {
            url: url.into(),
            user_code: None,
            completion: Box::pin(async move {
                let code = callback(listener, &nonce, account.0.app.name).await?;
                account.exchange(&code, &verifier, &redirect).await
            }),
        })
    }

    async fn device_flow(&self) -> Result<Flow> {
        let value =
            auth_json(self.post("/api/accounts/deviceauth/usercode").json(&json!({"client_id": CLIENT_ID}))).await?;
        let device = required(&value, "device_auth_id")?.to_owned();
        let code = required(&value, "user_code")?.to_owned();
        let mut interval =
            value["interval"].as_u64().or_else(|| value["interval"].as_str()?.parse().ok()).unwrap_or(5).max(1);
        let account = self.clone();
        Ok(Flow {
            url: format!("{}/codex/device", self.0.base),
            user_code: Some(code.clone()),
            completion: Box::pin(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                    let response = account
                        .post("/api/accounts/deviceauth/token")
                        .json(&json!({"device_auth_id": device, "user_code": code}))
                        .send()
                        .await
                        .map_err(http_error)?;
                    let status = response.status();
                    if status.is_success() {
                        let value: Value = response.json().await.map_err(http_error)?;
                        let redirect = format!("{}/deviceauth/callback", account.0.base);
                        return account
                            .exchange(
                                required(&value, "authorization_code")?,
                                required(&value, "code_verifier")?,
                                &redirect,
                            )
                            .await;
                    }
                    if matches!(status.as_u16(), 403 | 404) {
                        continue;
                    }
                    let error: Value = response.json().await.unwrap_or(Value::Null);
                    match error["error"].as_str().or(error["error"]["code"].as_str()) {
                        Some("slow_down") => interval += 5,
                        Some("deviceauth_authorization_pending") => {}
                        _ => bail!("ChatGPT refused the device code ({status})."),
                    }
                }
            }),
        })
    }

    async fn exchange(&self, code: &str, verifier: &str, redirect: &str) -> Result<Credential> {
        let request = self.post("/oauth/token").form(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", redirect),
        ]);
        token_credential(auth_json(request).await?, "")
    }
}

struct Flow {
    url: String,
    user_code: Option<String>,
    completion: Pin<Box<dyn Future<Output = Result<Credential>> + Send>>,
}

fn snapshot(state: &State) -> AccountSnapshot {
    let detail = state.refused.clone().or_else(|| state.failed.clone());
    let status = match (&state.pending, &detail, &state.credential) {
        (Some(_), ..) => Status::LoginPending,
        (None, Some(_), _) => Status::Error,
        (None, None, Some(_)) => Status::Connected,
        (None, None, None) => Status::SignedOut,
    };
    let credential = state.credential.as_ref();
    AccountSnapshot {
        provider_id: Provider::OpenAi,
        provider_label: "ChatGPT".into(),
        status,
        email: credential.and_then(|c| c.email.clone()),
        plan: credential.and_then(|c| c.plan.clone()),
        detail,
        sign_in_methods: vec![SignInMethod::Browser, SignInMethod::DeviceCode],
        login: state.pending.as_ref().map(|p| p.start.clone()),
        bound: None,
    }
}

/// Listens on the callback port. A sign-in this one replaced may still be letting go of it.
async fn listen(port: u16) -> Result<tokio::net::TcpListener> {
    let mut tries = 0;
    loop {
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => return Ok(listener),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse && tries < 50 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("listening for the sign-in on port {port} (is another sign-in open?)"));
            }
        }
    }
}

/// Serves the browser's return to the callback until it brings a code for this sign-in, then
/// stops listening.
async fn callback(listener: tokio::net::TcpListener, nonce: &str, app: &str) -> Result<String> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut request = vec![0; 8192];
        let read = stream.read(&mut request).await.unwrap_or(0);
        let request = String::from_utf8_lossy(&request[..read]);
        let target = request.split_whitespace().nth(1).unwrap_or_default();
        let url = url::Url::parse(&format!("http://localhost{target}")).ok();
        let query = |key: &str| url.as_ref()?.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned());
        let found = url.as_ref().is_some_and(|u| u.path() == "/auth/callback");
        let (status, body, code) = match (found, query("state"), query("code")) {
            (false, ..) => ("404 Not Found", "Not found.".to_owned(), None),
            (true, Some(state), Some(code)) if state == nonce && !code.is_empty() => {
                ("200 OK", format!("Signed in to {app}. You can close this window."), Some(code))
            }
            _ => ("400 Bad Request", format!("This sign-in did not match the one {app} started."), None),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
        if let Some(code) = code {
            return Ok(code);
        }
    }
}

fn claims(token: &str) -> Value {
    token
        .split('.')
        .nth(1)
        .and_then(|part| URL_SAFE_NO_PAD.decode(part.trim_end_matches('=')).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null)
}

/// The login in a token reply, keeping `refresh` when the reply brings no new refresh token.
fn token_credential(value: Value, refresh: &str) -> Result<Credential> {
    let access = required(&value, "access_token")?.to_owned();
    let claims = claims(&access);
    let auth = &claims["https://api.openai.com/auth"];
    let expires =
        value["expires_in"].as_u64().map(|s| now() + s * 1000).unwrap_or(claims["exp"].as_u64().unwrap_or(0) * 1000);
    let credential = Credential {
        refresh: value["refresh_token"].as_str().filter(|s| !s.is_empty()).unwrap_or(refresh).to_owned(),
        expires,
        account_id: required(auth, "chatgpt_account_id")?.to_owned(),
        email: claims["email"].as_str().map(str::to_owned),
        plan: auth["chatgpt_plan_type"].as_str().map(str::to_owned),
        access,
    };
    ensure!(!credential.refresh.is_empty(), "ChatGPT returned no refresh token.");
    ensure!(credential.expires > now(), "ChatGPT returned an expired login.");
    Ok(credential)
}

fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("ChatGPT's answer is missing {key}."))
}

fn http_error(error: reqwest::Error) -> anyhow::Error {
    anyhow!("Could not reach ChatGPT: {}", error.without_url())
}

async fn auth_json(request: reqwest::RequestBuilder) -> Result<Value> {
    let response = request.send().await.map_err(http_error)?;
    let status = response.status();
    ensure!(status.is_success(), "ChatGPT refused the sign-in ({status}).");
    response.json().await.map_err(http_error)
}
