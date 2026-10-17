//! The logins Eris apps' agents make model calls with: a ChatGPT login, made as the Codex CLI
//! makes one, and a Claude login, taken from Claude Code. Each account keeps its login in a file
//! only the user can read, refreshes it before it expires (once, however many callers ask), and
//! announces every change on a broadcast channel.
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! use erisagentauth::{Accounts, App};
//! let app = App { name: "ErisMaps", originator: "erismaps" };
//! let accounts = Accounts::load("/path/to/profile/accounts".as_ref(), app)?;
//! let mut events = accounts.subscribe();
//! let start = accounts.openai.login(erisagentauth::openai::Method::Browser).await?;
//! println!("open {}", start.url);
//! # Ok(()) }
//! ```

pub mod claude;
pub mod models;
#[cfg(feature = "harness")]
mod harness;
#[cfg(feature = "web")]
pub use harness::web_models;
pub mod openai;
mod storage;

use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::sync::broadcast;

/// The app signing in: its name shows on the page the browser lands on after a ChatGPT sign-in,
/// and its originator names it to OpenAI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct App {
    pub name: &'static str,
    pub originator: &'static str,
}

/// Whose login an account holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Provider {
    #[serde(rename = "openai")]
    OpenAi,
    #[serde(rename = "anthropic")]
    Anthropic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    SignedOut,
    LoginPending,
    Connected,
    /// The login stopped working, or a sign-in failed; `detail` says why.
    Error,
}

/// The ways an account can be signed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignInMethod {
    /// OAuth in the browser, back to a local callback.
    Browser,
    /// A code entered on a page, on this device or another.
    DeviceCode,
    /// The text of Claude Code's `.credentials.json`.
    CredentialsFile,
    /// The login macOS Claude Code keeps in the Keychain.
    Keychain,
    /// Claude Code's `.credentials.json`, read where it is on every call and never refreshed.
    BoundFile,
}

/// A sign-in under way: the page that finishes it, and for a device code the code to enter
/// there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStart {
    pub url: String,
    pub user_code: Option<String>,
}

/// An account as an app shows it, in the shape ErisDE shows ErisAE's accounts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSnapshot {
    pub provider_id: Provider,
    pub provider_label: String,
    pub status: Status,
    pub email: Option<String>,
    /// The subscription, such as `plus`, `pro` or `max`.
    pub plan: Option<String>,
    /// Why the status is `error`.
    pub detail: Option<String>,
    pub sign_in_methods: Vec<SignInMethod>,
    /// The sign-in under way, while the status is `login-pending`.
    pub login: Option<LoginStart>,
    /// The credentials file a bound login is read from.
    pub bound: Option<std::path::PathBuf>,
}

/// What accounts announce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", rename_all_fields = "camelCase")]
pub enum Event {
    /// An account changed; this is how it stands now.
    Account(AccountSnapshot),
    /// A sign-in finished, well or not.
    LoginCompleted { provider: Provider, ok: bool, error: Option<String> },
}

/// Both accounts, announcing on one channel. Their files are `chatgpt.json` and `claude.json`
/// in the directory they load from.
#[derive(Clone)]
pub struct Accounts {
    pub openai: openai::OpenAiAccount,
    pub claude: claude::ClaudeAccount,
    events: broadcast::Sender<Event>,
}

impl Accounts {
    /// The accounts kept in `dir`, created owner-only if it is missing, signing in and
    /// refreshing at the providers' own servers.
    pub fn load(dir: &Path, app: App) -> anyhow::Result<Self> {
        Self::load_from(dir, app, openai::AUTH, claude::API, claude::AUTH)
    }

    /// The accounts kept in `dir`, with the providers' servers at the given roots.
    pub fn load_from(
        dir: &Path,
        app: App,
        openai_auth: &str,
        claude_api: &str,
        claude_auth: &str,
    ) -> anyhow::Result<Self> {
        storage::private_dir(dir)?;
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            openai: openai::OpenAiAccount::load(dir.join("chatgpt.json"), openai_auth, app, events.clone())?,
            claude: claude::ClaudeAccount::load(dir.join("claude.json"), claude_api, claude_auth, events.clone())?,
            events,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn snapshots(&self) -> Vec<AccountSnapshot> {
        vec![self.openai.snapshot(), self.claude.snapshot()]
    }

    /// Ends any sign-in under way; afterwards the accounts give out no logins.
    pub async fn shutdown(&self) {
        self.openai.shutdown().await;
        self.claude.shutdown().await;
    }
}

/// A login this close to expiring is refreshed before it is used.
const REFRESH_MARGIN_MS: u64 = 120_000;

/// Unix milliseconds.
pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build().expect("an HTTP client")
}
