//! The Claude account: a Claude subscription's login, taken from the `.credentials.json` Claude
//! Code writes, or on macOS, where Claude Code keeps its login in the Keychain, from there; or a
//! long-lived token from `claude setup-token`. The account keeps its own copy of a Claude Code
//! login and refreshes it before it expires. Claude refresh tokens are single-use, so once the
//! account refreshes its copy, the Claude Code session it came from signs in again, and the other
//! way around. A setup token has no refresh token and does not expire, so it is shared with no
//! one.
use crate::storage::{read_json, write_json};
use crate::{AccountSnapshot, Event, Provider, REFRESH_MARGIN_MS, SignInMethod, Status, now};
use anyhow::{Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, broadcast};

/// The Anthropic API's root: Messages and models under `/v1`, a login's profile under `/api`.
pub const API: &str = "https://api.anthropic.com";
/// Where Claude logins refresh.
pub const AUTH: &str = "https://platform.claude.com";
/// Requests made with a Claude login's token name this beta.
pub const OAUTH_BETA: &str = "oauth-2025-04-20";
/// Claude Code's OAuth client, the only one its logins refresh through.
const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
/// What a login needs to make model calls.
const INFERENCE_SCOPE: &str = "user:inference";
/// The Keychain item macOS Claude Code keeps its login in.
const KEYCHAIN_SERVICE: &str = "Claude Code-credentials";
const NOT_A_LOGIN: &str =
    "This is not a Claude login file; choose the .credentials.json Claude Code keeps in ~/.claude";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeLogin {
    pub access: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<String>,
    /// Unix milliseconds. A login without an expiry, such as a long-lived token, never
    /// refreshes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    /// The Claude account's id, which Claude Code's requests name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The subscription, such as `pro` or `max`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
}

impl ClaudeLogin {
    /// The login in a Claude Code credentials file: its `claudeAiOauth` entry.
    pub fn parse(text: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(text).map_err(|_| anyhow!(NOT_A_LOGIN))?;
        let oauth = &value["claudeAiOauth"];
        let string = |key: &str| oauth[key].as_str().filter(|s| !s.is_empty()).map(str::to_owned);
        let access = string("accessToken").ok_or_else(|| anyhow!(NOT_A_LOGIN))?;
        if let Some(scopes) = oauth["scopes"].as_array() {
            ensure!(
                scopes.iter().any(|s| s == INFERENCE_SCOPE),
                "This Claude login cannot make model calls: it lacks the {INFERENCE_SCOPE} scope"
            );
        }
        Ok(Self {
            access,
            refresh: string("refreshToken"),
            expires: oauth["expiresAt"].as_u64(),
            account_id: None,
            email: None,
            plan: string("subscriptionType"),
        })
    }

    fn expiring(&self) -> bool {
        self.expires.is_some_and(|expires| expires <= now() + REFRESH_MARGIN_MS)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    version: u32,
    /// Stable for this installation; with the account id it names the device to Anthropic.
    install_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    login: Option<ClaudeLogin>,
}

struct State {
    login: Option<ClaudeLogin>,
    /// Why the stored login no longer works; cleared by adding a login.
    refused: Option<String>,
    stopped: bool,
}

#[derive(Clone)]
pub struct ClaudeAccount(Arc<Inner>);

struct Inner {
    path: PathBuf,
    install_id: String,
    /// The Anthropic API's root, where a login's profile is read.
    api: String,
    /// Where logins refresh.
    auth: String,
    client: reqwest::Client,
    events: broadcast::Sender<Event>,
    state: AsyncMutex<State>,
    snapshot: Mutex<AccountSnapshot>,
}

impl ClaudeAccount {
    /// The login stored at `path`, checked against the Anthropic API at `api_base` ([`API`])
    /// and refreshed at `auth_base` ([`AUTH`]), announcing its changes on `events`. A new file
    /// is written straight away, so the install id is the same from the first run on.
    pub fn load(path: PathBuf, api_base: &str, auth_base: &str, events: broadcast::Sender<Event>) -> Result<Self> {
        let stored = match read_json::<Stored>(&path)? {
            Some(stored) => {
                ensure!(stored.version == 1, "unsupported Claude account version {}", stored.version);
                ensure!(!stored.install_id.is_empty(), "the stored Claude account has no install id");
                stored
            }
            None => {
                let stored = Stored { version: 1, install_id: uuid::Uuid::new_v4().to_string(), login: None };
                write_json(&path, &stored)?;
                stored
            }
        };
        let state = State { login: stored.login, refused: None, stopped: false };
        Ok(Self(Arc::new(Inner {
            snapshot: Mutex::new(snapshot(&state)),
            path,
            install_id: stored.install_id,
            api: api_base.trim_end_matches('/').to_owned(),
            auth: auth_base.trim_end_matches('/').to_owned(),
            client: crate::client(),
            events,
            state: AsyncMutex::new(state),
        })))
    }

    pub fn install_id(&self) -> &str {
        &self.0.install_id
    }

    pub fn snapshot(&self) -> AccountSnapshot {
        self.0.snapshot.lock().unwrap().clone()
    }

    pub async fn signed_in(&self) -> bool {
        self.0.state.lock().await.login.is_some()
    }

    fn changed(&self, state: &State) {
        let value = snapshot(state);
        *self.0.snapshot.lock().unwrap() = value.clone();
        let _ = self.0.events.send(Event::Account(value));
    }

    /// The login, refreshed first when it is about to expire. Concurrent callers share one
    /// refresh.
    pub async fn current(&self) -> Result<ClaudeLogin> {
        let mut state = self.0.state.lock().await;
        ensure!(!state.stopped, "the Claude account is shut down");
        if let Some(refused) = &state.refused {
            bail!("{refused}");
        }
        let login = state.login.clone().ok_or_else(|| anyhow!("Add a Claude login to use Claude models."))?;
        if !login.expiring() {
            return Ok(login);
        }
        match self.refresh(&login).await {
            Ok(fresh) => {
                self.save(&mut state, Some(fresh.clone()))?;
                self.changed(&state);
                Ok(fresh)
            }
            Err(Refresh::Refused(refused)) => {
                state.refused = Some(refused.clone());
                self.changed(&state);
                bail!("{refused}")
            }
            Err(Refresh::Failed(error)) => Err(error),
        }
    }

    /// Signs in with a Claude Code credentials file's text, once Anthropic accepts the login.
    /// Replies with the account as it now stands.
    pub async fn import(&self, text: &str) -> Result<AccountSnapshot> {
        let mut login = ClaudeLogin::parse(text)?;
        let mut state = self.0.state.lock().await;
        ensure!(!state.stopped, "the Claude account is shut down");
        if login.expiring() {
            login = match self.refresh(&login).await {
                Ok(fresh) => fresh,
                Err(Refresh::Refused(refused)) => bail!("{refused}"),
                Err(Refresh::Failed(error)) => return Err(error),
            };
        }
        let profile = self.profile(&login.access).await?;
        fill(&mut login, &profile);
        self.save(&mut state, Some(login))?;
        state.refused = None;
        self.changed(&state);
        Ok(snapshot(&state))
    }

    /// Signs in with a long-lived token from `claude setup-token` (`sk-ant-oat…`), once
    /// Anthropic accepts it. The account, email and plan come from the login's profile; a token
    /// made for model calls alone may not read it, and is then checked against the model list.
    pub async fn import_token(&self, token: &str) -> Result<AccountSnapshot> {
        let token = token.trim();
        ensure!(
            token.starts_with("sk-ant-oat") && !token.contains(char::is_whitespace),
            "This is not a Claude setup token; run `claude setup-token` and give the sk-ant-oat… token it prints"
        );
        let mut state = self.0.state.lock().await;
        ensure!(!state.stopped, "the Claude account is shut down");
        let mut login = ClaudeLogin {
            access: token.to_owned(),
            refresh: None,
            expires: None,
            account_id: None,
            email: None,
            plan: None,
        };
        match self.profile_status(token).await? {
            (status, Some(profile)) if status.is_success() => fill(&mut login, &profile),
            (status, _) if status == reqwest::StatusCode::FORBIDDEN => self.models_accept(token).await?,
            (status, _) => bail!("Anthropic refused this token ({status}); make a new one with `claude setup-token`"),
        }
        self.save(&mut state, Some(login))?;
        state.refused = None;
        self.changed(&state);
        Ok(snapshot(&state))
    }

    /// Signs in with the login macOS Claude Code keeps in the Keychain.
    pub async fn import_keychain(&self) -> Result<AccountSnapshot> {
        ensure!(cfg!(target_os = "macos"), "Only macOS keeps Claude Code's login in the Keychain");
        let output = tokio::process::Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"])
            .output()
            .await
            .map_err(|e| anyhow!("Could not read the Keychain: {e}"))?;
        ensure!(
            output.status.success(),
            "The Keychain has no Claude Code login, or access to it was refused; sign in with `claude` first"
        );
        self.import(String::from_utf8_lossy(&output.stdout).trim()).await
    }

    pub async fn logout(&self) -> Result<()> {
        let mut state = self.0.state.lock().await;
        self.save(&mut state, None)?;
        state.refused = None;
        self.changed(&state);
        Ok(())
    }

    /// Afterwards the account gives out no login.
    pub async fn shutdown(&self) {
        self.0.state.lock().await.stopped = true;
    }

    fn save(&self, state: &mut State, login: Option<ClaudeLogin>) -> Result<()> {
        let stored = Stored { version: 1, install_id: self.0.install_id.clone(), login };
        write_json(&self.0.path, &stored)?;
        state.login = stored.login;
        Ok(())
    }

    /// The account and organization the token belongs to, which also proves Anthropic accepts
    /// it.
    async fn profile_status(&self, access: &str) -> Result<(reqwest::StatusCode, Option<Value>)> {
        let response = self
            .0
            .client
            .get(format!("{}/api/oauth/profile", self.0.api))
            .bearer_auth(access)
            .header("anthropic-beta", OAUTH_BETA)
            .send()
            .await
            .map_err(connection)?;
        let status = response.status();
        let body = if status.is_success() { Some(response.json().await.map_err(connection)?) } else { None };
        Ok((status, body))
    }

    /// Whether Anthropic lets the token list models, which any token that can make model calls
    /// may.
    async fn models_accept(&self, access: &str) -> Result<()> {
        let response = self
            .0
            .client
            .get(format!("{}/v1/models?limit=1", self.0.api))
            .bearer_auth(access)
            .header("anthropic-beta", OAUTH_BETA)
            .header("anthropic-version", "2023-06-01")
            .send()
            .await
            .map_err(connection)?;
        let status = response.status();
        ensure!(
            status.is_success(),
            "Anthropic refused this token ({status}); make a new one with `claude setup-token`"
        );
        Ok(())
    }

    async fn profile(&self, access: &str) -> Result<Value> {
        let response = self
            .0
            .client
            .get(format!("{}/api/oauth/profile", self.0.api))
            .bearer_auth(access)
            .header("anthropic-beta", OAUTH_BETA)
            .send()
            .await
            .map_err(connection)?;
        let status = response.status();
        ensure!(
            status.is_success(),
            "Anthropic refused this Claude login ({status}); sign in with Claude Code again and add the new login"
        );
        response.json().await.map_err(connection)
    }

    async fn refresh(&self, login: &ClaudeLogin) -> Result<ClaudeLogin, Refresh> {
        let Some(refresh) = &login.refresh else {
            return Err(Refresh::Refused(
                "This Claude login has expired; sign in with Claude Code again and add the new login".into(),
            ));
        };
        let response = self
            .0
            .client
            .post(format!("{}/v1/oauth/token", self.0.auth))
            .json(&json!({"grant_type": "refresh_token", "refresh_token": refresh, "client_id": CLIENT_ID}))
            .send()
            .await
            .map_err(|e| Refresh::Failed(connection(e)))?;
        let status = response.status();
        if matches!(status.as_u16(), 400 | 401 | 403) {
            return Err(Refresh::Refused(
                "Anthropic no longer accepts this Claude login: it was refreshed elsewhere or signed out. Add a fresh login"
                    .into(),
            ));
        }
        if !status.is_success() {
            return Err(Refresh::Failed(anyhow!("refreshing the Claude login failed ({status})")));
        }
        let value: Value = response.json().await.map_err(|e| Refresh::Failed(connection(e)))?;
        let access = value["access_token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Refresh::Failed(anyhow!("Anthropic's refresh reply has no access token")))?;
        let expires_in = value["expires_in"]
            .as_u64()
            .ok_or_else(|| Refresh::Failed(anyhow!("Anthropic's refresh reply has no expiry")))?;
        let account = &value["account"];
        Ok(ClaudeLogin {
            access: access.into(),
            refresh: value["refresh_token"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .or_else(|| login.refresh.clone()),
            expires: Some(now() + expires_in * 1000),
            account_id: account["uuid"].as_str().map(str::to_owned).or_else(|| login.account_id.clone()),
            email: account["email_address"].as_str().map(str::to_owned).or_else(|| login.email.clone()),
            plan: login.plan.clone(),
        })
    }
}

/// The account, email and plan a login's profile names, where the login lacks them.
fn fill(login: &mut ClaudeLogin, profile: &Value) {
    login.account_id = profile["account"]["uuid"].as_str().map(str::to_owned).or(login.account_id.take());
    login.email = profile["account"]["email"].as_str().map(str::to_owned).or(login.email.take());
    if login.plan.is_none() {
        login.plan = profile["organization"]["organization_type"]
            .as_str()
            .map(|kind| kind.strip_prefix("claude_").unwrap_or(kind).to_owned());
    }
}

enum Refresh {
    /// Anthropic turned the login down; only a new login helps.
    Refused(String),
    /// The refresh did not get an answer; a later one may.
    Failed(anyhow::Error),
}

fn connection(error: reqwest::Error) -> anyhow::Error {
    anyhow!("Anthropic connection failed: {}", error.without_url())
}

fn snapshot(state: &State) -> AccountSnapshot {
    let status = match (&state.login, &state.refused) {
        (_, Some(_)) => Status::Error,
        (Some(_), None) => Status::Connected,
        (None, None) => Status::SignedOut,
    };
    let mut sign_in_methods = vec![SignInMethod::CredentialsFile, SignInMethod::SetupToken];
    if cfg!(target_os = "macos") {
        sign_in_methods.push(SignInMethod::Keychain);
    }
    let login = state.login.as_ref();
    AccountSnapshot {
        provider_id: Provider::Anthropic,
        provider_label: "Claude".into(),
        status,
        email: login.and_then(|l| l.email.clone()),
        plan: login.and_then(|l| l.plan.clone()),
        detail: state.refused.clone(),
        sign_in_methods,
        login: None,
    }
}
