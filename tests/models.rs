//! The models each login offers, listed by its own provider: ChatGPT's from the Codex
//! endpoint, Claude's from Anthropic's API, ChatGPT's first.

mod support;

use erisagentauth::Accounts;
use erisagentauth::models::{ANTHROPIC, CODEX};
use serde_json::json;
use support::*;

/// Both accounts in a fresh directory: ChatGPT signed in when `chatgpt`, and Claude bound to a
/// Claude Code credentials file when `claude`.
async fn logins(chatgpt: bool, claude: bool) -> (Accounts, AccountFile, String, std::sync::Arc<Counts>, Vec<Served>) {
    let (openai, openai_counts, openai_served) = openai_server().await;
    let (anthropic, claude_counts, claude_served) = claude_server().await;
    let file = AccountFile::new();
    let dir = file.path.parent().unwrap().join("accounts");
    if chatgpt {
        std::fs::create_dir_all(&dir).unwrap();
        let stored = json!({"version": 1, "credential": {
            "access": chatgpt_token(3600), "refresh": "refresh-1", "expires": now() + 3_600_000,
            "accountId": "account-1", "email": null, "plan": null,
        }});
        std::fs::write(dir.join("chatgpt.json"), stored.to_string()).unwrap();
    }
    let accounts = Accounts::load_from(&dir, APP, &openai, &anthropic, &anthropic).unwrap();
    if claude {
        let credentials = file.path.with_file_name(".credentials.json");
        write_credentials(&credentials, "bound-token", 3_600_000);
        accounts.claude.bind(&credentials).await.unwrap();
    }
    // Counts from both servers in one.
    let counts = std::sync::Arc::new(Counts::default());
    let (o, c) = (openai_counts.clone(), claude_counts.clone());
    let sum = counts.clone();
    tokio::spawn(async move {
        loop {
            let total = Counts::get(&o.listings) + Counts::get(&c.listings);
            sum.listings.store(total, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    });
    (accounts, file, format!("{openai}/codex"), counts, vec![openai_served, claude_served])
}

#[tokio::test]
async fn both_logins_list_their_models_chatgpt_first() {
    let (accounts, _file, codex, _counts, _served) = logins(true, true).await;
    let models = accounts.models(&codex).await.unwrap();
    let listed: Vec<(&str, &str)> = models.iter().map(|m| (m.provider.as_str(), m.id.as_str())).collect();
    assert_eq!(
        listed,
        [
            (CODEX, "gpt-9-sol"),
            (CODEX, "gpt-9-luna"),
            (ANTHROPIC, "claude-haiku-9"),
            (ANTHROPIC, "claude-sonnet-9"),
            (ANTHROPIC, "claude-old-4-5"),
        ],
        "the hidden Codex model is left out, and both pages of Claude's are read"
    );
    let named = |id: &str| models.iter().find(|m| m.id == id).unwrap();
    assert_eq!(named("gpt-9-luna").efforts, ["low", "medium"]);
    assert_eq!(named("gpt-9-sol").context_window, Some(400000));
    assert_eq!(named("claude-haiku-9").efforts, ["low", "medium", "high"]);
    assert_eq!(named("claude-sonnet-9").efforts, ["low", "medium", "high", "xhigh", "max"]);
    assert!(named("claude-haiku-9").cannot_run.is_none());
    assert!(named("claude-old-4-5").cannot_run.is_some(), "it thinks only on a budget");
    assert!(named("gpt-9-luna").small() && !named("gpt-9-sol").small());
}

#[tokio::test]
async fn a_login_that_is_not_signed_in_offers_no_models() {
    let (accounts, _file, codex, _counts, _served) = logins(false, true).await;
    let models = accounts.models(&codex).await.unwrap();
    assert!(models.iter().all(|m| m.provider == ANTHROPIC) && !models.is_empty());
    let (accounts, _file, codex, _counts, _served) = logins(false, false).await;
    assert!(accounts.models(&codex).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_listing_is_kept_for_a_while() {
    let (accounts, _file, codex, counts, _served) = logins(true, true).await;
    accounts.models(&codex).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let first = Counts::get(&counts.listings);
    assert_eq!(first, 3, "one Codex listing and two pages of Claude's");
    accounts.models(&codex).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert_eq!(Counts::get(&counts.listings), first);
}

#[cfg(feature = "web")]
#[tokio::test]
async fn web_search_runs_on_claudes_haiku_or_else_chatgpts_small_model() {
    use erisharness::provider::{Provider, RateGate};
    use std::sync::Arc;
    let (accounts, _file, codex_api, _counts, _served) = logins(true, true).await;
    let codex: Arc<dyn Provider> = Arc::new(accounts.openai.codex(&codex_api, RateGate::new(4, 16), 0));
    let anthropic: Arc<dyn Provider> = Arc::new(accounts.claude.anthropic(0).await.unwrap());
    let models = accounts.models(&codex_api).await.unwrap();

    let both = erisagentauth::web_models(&models, codex.clone(), anthropic.clone());
    let searcher = both.searcher.unwrap();
    assert_eq!((searcher.model.as_str(), searcher.effort.as_deref()), ("claude-haiku-9", Some("low")));
    assert!(Arc::ptr_eq(&searcher.provider, &anthropic));
    assert_eq!(both.reader.unwrap().model, "claude-haiku-9");

    let chatgpt: Vec<_> = models.iter().filter(|m| m.provider == CODEX).cloned().collect();
    let alone = erisagentauth::web_models(&chatgpt, codex.clone(), anthropic.clone()).searcher.unwrap();
    assert_eq!(alone.model, "gpt-9-luna");
    assert!(Arc::ptr_eq(&alone.provider, &codex));

    assert!(erisagentauth::web_models(&[], codex, anthropic).searcher.is_none());
}
