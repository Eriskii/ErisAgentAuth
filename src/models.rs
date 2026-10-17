//! The models each login offers, listed by its own provider: ChatGPT's through the Codex
//! endpoint, Claude's through Anthropic's API. A listing is kept for an hour per login. Claude
//! models run with adaptive thinking at the efforts their capabilities list; one that thinks only
//! on a budget is listed with why it cannot run.

use crate::claude::{self, ClaudeAccount};
use crate::openai::OpenAiAccount;
use crate::{Accounts, now};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The names ErisHarness apps give the providers these logins call: the Codex endpoint with
/// the ChatGPT login, and Anthropic's API with the Claude login.
pub const CODEX: &str = "codex";
pub const ANTHROPIC: &str = "anthropic";

/// The Codex endpoint lists models by the client version asking; this asks as a current one.
const CLIENT_VERSION: &str = "99.0.0";
/// The efforts adaptive thinking takes, in order.
const CLAUDE_EFFORTS: [&str; 5] = ["low", "medium", "high", "xhigh", "max"];
/// How long a listing serves.
pub(crate) const KEEP_FOR_MS: u64 = 3_600_000;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Model {
    /// [`CODEX`] or [`ANTHROPIC`].
    pub provider: String,
    pub id: String,
    pub name: String,
    pub context_window: Option<u64>,
    /// The reasoning efforts the model takes, lowest first.
    pub efforts: Vec<String>,
    /// Why agents cannot run on it, if they cannot.
    pub cannot_run: Option<String>,
}

impl Model {
    /// Whether it is a provider's small, cheap model, as ChatGPT's luna and mini are.
    pub fn small(&self) -> bool {
        ["mini", "nano", "spark", "small", "lite", "luna", "haiku"].iter().any(|w| self.id.contains(w))
    }
}

/// A listing and whose login it was for.
pub(crate) type Kept = Option<(String, u64, Vec<Model>)>;

impl OpenAiAccount {
    /// The models the signed-in ChatGPT login offers at the Codex endpoint `codex_api`, most
    /// preferred first; none when it is not signed in.
    pub async fn models(&self, codex_api: &str) -> Result<Vec<Model>> {
        if !self.signed_in().await {
            return Ok(Vec::new());
        }
        let credential = self.current().await?;
        let mut kept = self.kept_models().lock().await;
        if let Some((account, at, models)) = kept.as_ref()
            && *account == credential.account_id
            && now() - at < KEEP_FOR_MS
        {
            return Ok(models.clone());
        }
        let response = crate::client()
            .get(format!("{}/models?client_version={CLIENT_VERSION}", codex_api.trim_end_matches('/')))
            .bearer_auth(&credential.access)
            .header("chatgpt-account-id", &credential.account_id)
            .header("originator", self.app().originator)
            .send()
            .await?;
        let status = response.status();
        ensure!(status.is_success(), "ChatGPT did not list its models ({status}).");
        let models = codex_models(&response.json().await?);
        *kept = Some((credential.account_id, now(), models.clone()));
        Ok(models)
    }
}

impl ClaudeAccount {
    /// The models the Claude login offers at Anthropic's API, newest first; none when it is
    /// not signed in.
    pub async fn models(&self) -> Result<Vec<Model>> {
        if !self.signed_in().await {
            return Ok(Vec::new());
        }
        let login = self.current().await?;
        let who = login.account_id.clone().unwrap_or_default();
        let mut kept = self.kept_models().lock().await;
        if let Some((account, at, models)) = kept.as_ref()
            && *account == who
            && now() - at < KEEP_FOR_MS
        {
            return Ok(models.clone());
        }
        let client = crate::client();
        let mut models = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let mut request = client
                .get(format!("{}/v1/models", self.api()))
                .query(&[("limit", "1000")])
                .bearer_auth(&login.access)
                .header("anthropic-version", "2023-06-01")
                .header("anthropic-beta", claude::OAUTH_BETA);
            if let Some(after) = &after {
                request = request.query(&[("after_id", after)]);
            }
            let response = request.send().await?;
            let status = response.status();
            ensure!(status.is_success(), "Anthropic did not list the Claude login's models ({status}).");
            let page: Value = response.json().await?;
            models.extend(claude_models(&page));
            match page["last_id"].as_str() {
                Some(last) if page["has_more"] == true => after = Some(last.to_owned()),
                _ => break,
            }
        }
        *kept = Some((who, now(), models.clone()));
        Ok(models)
    }
}

impl Accounts {
    /// Both logins' models: ChatGPT's (at `codex_api`), then Claude's. A login whose listing
    /// fails fails the call only when the other offers none.
    pub async fn models(&self, codex_api: &str) -> Result<Vec<Model>> {
        match tokio::join!(self.openai.models(codex_api), self.claude.models()) {
            (Ok(mut codex), Ok(claude)) => {
                codex.extend(claude);
                Ok(codex)
            }
            (Ok(models), Err(_)) | (Err(_), Ok(models)) if !models.is_empty() => Ok(models),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}

fn codex_models(body: &Value) -> Vec<Model> {
    body["models"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["visibility"] == "list")
        .filter_map(|m| {
            let id = m["slug"].as_str()?;
            Some(Model {
                provider: CODEX.into(),
                id: id.to_owned(),
                name: m["display_name"].as_str().unwrap_or(id).to_owned(),
                context_window: m["context_window"].as_u64(),
                efforts: m["supported_reasoning_levels"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|l| l["effort"].as_str().map(str::to_owned))
                    .collect(),
                cannot_run: None,
            })
        })
        .collect()
}

fn claude_models(body: &Value) -> Vec<Model> {
    let supported = |capability: &Value| capability["supported"] == true;
    body["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| {
            let id = m["id"].as_str()?;
            let capabilities = &m["capabilities"];
            let adaptive = supported(&capabilities["thinking"]["types"]["adaptive"]);
            let effort = &capabilities["effort"];
            Some(Model {
                provider: ANTHROPIC.into(),
                id: id.to_owned(),
                name: m["display_name"].as_str().unwrap_or(id).to_owned(),
                context_window: m["max_input_tokens"].as_u64(),
                efforts: CLAUDE_EFFORTS
                    .iter()
                    .filter(|level| adaptive && supported(effort) && supported(&effort[**level]))
                    .map(|level| level.to_string())
                    .collect(),
                cannot_run: (!adaptive).then(|| format!("{id} thinks only on a budget, and agents run on adaptive thinking")),
            })
        })
        .collect()
}
