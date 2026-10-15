# ErisAgentAuth

The logins Eris apps' agents make model calls with: a ChatGPT login, made the way the Codex CLI
makes one, and a Claude login, taken from Claude Code. Crate `erisagentauth`.

```toml
erisagentauth = { git = "https://github.com/Eriskii/ErisAgentAuth", tag = "v0.2.0" }
```

Feature `harness` (on by default) makes both accounts `erisharness::provider::Credentials`.

| Module    | What it holds                                                                               |
| --------- | ------------------------------------------------------------------------------------------- |
| `openai`  | `OpenAiAccount`: browser sign-in (OAuth with PKCE, back to `localhost:1455`) or device code |
| `claude`  | `ClaudeAccount`: a `claude setup-token` token, Claude Code's `.credentials.json`, or its macOS Keychain item |
| (root)    | `Accounts` (both, on one channel), `AccountSnapshot`, `Event`, `App`, `LoginStart`          |

## Using it

```rust
use erisagentauth::{Accounts, App, Event, openai::Method};

let accounts = Accounts::load(&profile.join("accounts"), App { name: "ErisMaps", originator: "erismaps" })?;
let mut events = accounts.subscribe();

let start = accounts.openai.login(Method::Browser).await?; // or Method::DeviceCode
open_in_browser(&start.url); // a device code also shows start.user_code

while let Ok(event) = events.recv().await {
    match event {
        Event::Account(snapshot) => show(snapshot),
        Event::LoginCompleted { provider, ok, error } => break,
    }
}

// Every model call asks for the login; one about to expire is refreshed first, once.
let credential = accounts.openai.current().await?;
```

`Accounts::load` keeps `chatgpt.json` and `claude.json` in the directory, which it creates
owner-only. An app needing one account loads it alone with `OpenAiAccount::load` or
`ClaudeAccount::load`, giving the file, the provider's servers and a broadcast sender.

With ErisHarness, the accounts are the credentials:

```rust
let provider = Responses::new(ResponsesConfig {
    base_url: erisagentauth::openai::CODEX_API.into(),
    headers: vec![("originator".into(), "erismaps".into())],
    credentials: Arc::new(accounts.openai.clone()),
    ..
});
let identity = accounts.claude.claude_code().await;
let config = AnthropicConfig::new(Arc::new(accounts.claude.clone()), AnthropicAuth::ClaudeCode(identity));
```

## Snapshots and events

`AccountSnapshot` is the account in the shape ErisDE shows ErisAE's accounts:

```json
{ "providerId": "openai", "providerLabel": "ChatGPT", "status": "login-pending",
  "email": null, "plan": null, "detail": null, "signInMethods": ["browser", "device-code"],
  "login": { "url": "https://auth.openai.com/oauth/authorize?…", "userCode": null } }
```

`status` is `signed-out`, `login-pending`, `connected`, or `error`, with `detail` saying why.
Every change sends `Event::Account`; every sign-in ends with `Event::LoginCompleted`. Both
serialize with a `type` tag (`account`, `login-completed`).

## Refreshing

Each account holds its login behind one lock, so concurrent `current()` calls share a single
refresh. A refresh the provider turns down (400, 401, 403) puts the account in `error` and keeps
it there, without asking again, until a new sign-in; a refresh that gets no answer fails that
call only.

Claude refresh tokens are single-use. Once the account refreshes the login it took from Claude
Code, that Claude Code session has to sign in again, and the other way around.

## Claude logins

`ClaudeAccount::import_token` takes a long-lived token from `claude setup-token`
(`sk-ant-oat…`). It has no refresh token and no expiry, so it never refreshes and signs nobody
out. Anthropic has to accept it first: the account, email and plan come from the login's profile,
and a token that may not read the profile (403) is checked against the model list instead, with
no email or plan. This is the way to sign in an app without sharing Claude Code's login.

`import` takes Claude Code's `.credentials.json` text and `import_keychain` its macOS Keychain
item. Both share Claude Code's single-use refresh token: the first refresh on either side signs
the other out. Signing Claude Code in with its own `CLAUDE_CONFIG_DIR` for the app avoids that.

## Files

Logins are written owner-only (`0600`) through a temporary file and a rename, so a file is
whole or absent. `chatgpt.json` is `{"version": 1, "credential": {…}}`; `claude.json` is
`{"version": 1, "installId": "…", "login": {…}}`, written on first load so the install id that
names the device to Anthropic stays the same from the first run on. Signing out of ChatGPT
removes its file; signing out of Claude keeps the install id.

## Tests

`cargo test` runs both accounts against stand-in auth servers on local ports: browser sign-ins
through their real callback, device-code polling, concurrent refreshes, refused refreshes, and
file permissions.
