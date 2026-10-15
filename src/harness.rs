//! Both accounts as ErisHarness credentials. Each request asks its account, so a refreshed
//! login reaches running agents.
use crate::claude::ClaudeAccount;
use crate::openai::OpenAiAccount;
use anyhow::Result;
use erisharness::provider::{Authorization, ClaudeCode, Credentials};
use futures_util::future::BoxFuture;

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
}
