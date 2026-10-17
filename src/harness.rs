//! Both accounts as ErisHarness credentials and providers. Each request asks its account, so a
//! refreshed login reaches running agents.
use crate::claude::ClaudeAccount;
use crate::openai::OpenAiAccount;
use anyhow::Result;
use erisharness::provider::{
    Anthropic, AnthropicAuth, AnthropicConfig, Authorization, ClaudeCode, Credentials, RateGate, Responses,
    ResponsesConfig, Thinking,
};
use futures_util::future::BoxFuture;
use std::sync::Arc;

/// A ChatGPT login's token, naming its account in `chatgpt-account-id`, as the Codex
/// endpoint wants.
impl Credentials for OpenAiAccount {
    fn authorize(&self) -> BoxFuture<'_, Result<Authorization>> {
        Box::pin(async move {
            let credential = self.current().await?;
            Ok(Authorization {
                token: credential.access,
                headers: vec![("chatgpt-account-id".into(), credential.account_id)],
            })
        })
    }
}

/// A Claude login's token. The rest of what Claude Code's requests carry comes from
/// `AnthropicAuth::ClaudeCode` with [`ClaudeAccount::claude_code`].
impl Credentials for ClaudeAccount {
    fn authorize(&self) -> BoxFuture<'_, Result<Authorization>> {
        Box::pin(async move { Ok(Authorization { token: self.current().await?.access, headers: Vec::new() }) })
    }
}

impl ClaudeAccount {
    /// The Claude Code installation requests claim to come from: this account's install id and
    /// its signed-in Claude account, if any.
    pub async fn claude_code(&self) -> ClaudeCode {
        let account_id = self.current().await.ok().and_then(|login| login.account_id);
        ClaudeCode { install_id: self.install_id().to_owned(), account_id, version: None }
    }

    /// ErisHarness's Anthropic provider on this login's API, calling as Claude Code. Each
    /// agent's reasoning effort reaches Claude as the effort of its adaptive thinking, which is
    /// how the efforts [`models`](Self::models) lists are taken.
    pub async fn anthropic(&self, max_retries: u32) -> Result<Anthropic> {
        let mut config = AnthropicConfig::new(Arc::new(self.clone()), AnthropicAuth::ClaudeCode(self.claude_code().await));
        config.base_url = format!("{}/v1", self.api());
        config.max_retries = max_retries;
        config.thinking = Thinking::Adaptive { display: false };
        Anthropic::new(config)
    }
}

impl OpenAiAccount {
    /// ErisHarness's Responses provider on the Codex endpoint `codex_api`, as the Codex CLI
    /// calls it, naming the app as its originator.
    pub fn codex(&self, codex_api: &str, gate: Arc<RateGate>, max_retries: u32) -> Responses {
        Responses::new(ResponsesConfig {
            base_url: codex_api.trim_end_matches('/').to_owned(),
            headers: vec![
                ("OpenAI-Beta".into(), "responses=experimental".into()),
                ("originator".into(), self.app().originator.into()),
            ],
            store: false,
            max_retries,
            credentials: Arc::new(self.clone()),
            gate,
        })
    }
}

/// What ErisHarness's `web` tool searches and reads pages with, from both logins' models: with
/// Claude, its newest Haiku, searching with Claude's hosted search; with ChatGPT alone, its small
/// model, searching with OpenAI's; low effort when the model takes it. With neither, search falls
/// back to DuckDuckGo and pages are not read.
#[cfg(feature = "web")]
pub fn web_models(
    models: &[crate::models::Model],
    codex: Arc<dyn erisharness::provider::Provider>,
    anthropic: Arc<dyn erisharness::provider::Provider>,
) -> erisharness::tools::web::Models {
    use crate::models::{ANTHROPIC, CODEX};
    let runs = |m: &&crate::models::Model| m.cannot_run.is_none() && m.small();
    let chosen = models
        .iter()
        .filter(runs)
        .find(|m| m.provider == ANTHROPIC)
        .map(|m| (anthropic.clone(), m))
        .or_else(|| models.iter().filter(runs).find(|m| m.provider == CODEX).map(|m| (codex.clone(), m)));
    let model = chosen.map(|(provider, m)| erisharness::tools::web::Model {
        provider,
        model: m.id.clone(),
        effort: m.efforts.iter().any(|e| e == "low").then(|| "low".to_owned()),
    });
    erisharness::tools::web::Models { searcher: model.clone(), reader: model, ..Default::default() }
}
