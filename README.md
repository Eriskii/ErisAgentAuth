# ErisAgentAuth

The logins Eris apps' agents make model calls with: a ChatGPT login, made the way the Codex CLI
makes one, and a Claude login, taken from Claude Code. Crate `erisagentauth`.

```toml
erisagentauth = { git = "https://github.com/Eriskii/ErisAgentAuth", tag = "v0.3.0" }
```

Feature `harness` (on by default) makes both accounts `erisharness::provider::Credentials` and
builds the providers they call; feature `web` adds `web_models`, what ErisHarness's `web` tool
searches and reads with.

| Module    | What it holds                                                                               |
| --------- | ------------------------------------------------------------------------------------------- |
| `openai`  | `OpenAiAccount`: browser sign-in (OAuth with PKCE, back to `localhost:1455`) or device code |
| `claude`  | `ClaudeAccount`: Claude Code's `.credentials.json` imported or bound, or its macOS Keychain item; `claude_code_credentials()`, where Claude Code keeps it |
| `models`  | `Model`, and the models each login offers: `OpenAiAccount::models`, `ClaudeAccount::models`, `Accounts::models` |
| (root)    | `Accounts` (both, on one channel), `AccountSnapshot`, `Event`, `App`, `LoginStart`, `web_models` |

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

With ErisHarness, the accounts are the credentials, and build the providers that call with them:

```rust
use erisagentauth::models::{ANTHROPIC, CODEX};

// The Codex endpoint as the Codex CLI calls it, naming the app as its originator.
let codex = Arc::new(accounts.openai.codex(erisagentauth::openai::CODEX_API, RateGate::new(64, 512), 5));
// Anthropic's API as Claude Code calls it; an agent's effort is its adaptive thinking's.
let anthropic = Arc::new(accounts.claude.anthropic(5).await?);
let harness = Harness::builder(state).provider(CODEX, codex.clone()).provider(ANTHROPIC, anthropic.clone());

// What agents can run on: ChatGPT's models, then Claude's, each with the efforts it takes.
let models = accounts.models(erisagentauth::openai::CODEX_API).await?;
// What `web` searches and reads with: Claude's Haiku, or else ChatGPT's small model.
let web = erisharness::tools::web::Web::new(http, erisagentauth::web_models(&models, codex, anthropic));
```

## Models

`OpenAiAccount::models(codex_api)` lists the ChatGPT login's models from the Codex endpoint
(those shown in pickers, most preferred first); `ClaudeAccount::models()` lists the Claude
login's from Anthropic's API, every page, newest first. A model's `efforts` are the reasoning
efforts it takes. Claude models run with adaptive thinking, so their efforts are those their
capabilities list for it, and one that thinks only on a budget has `cannot_run` saying so. A
login that is not signed in lists none; each listing is kept for an hour per login.
`Accounts::models` gives both, ChatGPT's first, failing only when one fails and the other has
none. `Model::small` names a provider's small model (luna, mini, haiku…).

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

Claude refresh tokens are single-use. Once the account refreshes a login it imported from Claude
Code, that Claude Code session has to sign in again, and the other way around.

## Binding a Claude login

`ClaudeAccount::bind(path)` keeps only the path of a Claude Code `.credentials.json`. Every
`current()` reads the login from that file as it is then, and the account never refreshes it:
Claude Code refreshes its own file, the account takes the new token, and no session is signed
out. When the file's token has expired (or the file is gone), `current()` fails and the snapshot
shows `error` with the reason, until the file holds a fresh token again. The binding lasts
across runs until `import`, `import_keychain`, another `bind` or `logout` replaces it. The
snapshot's `bound` is the file's path.

## Files

Logins are written owner-only (`0600`) through a temporary file and a rename, so a file is
whole or absent. `chatgpt.json` is `{"version": 1, "credential": {…}}`; `claude.json` is
`{"version": 1, "installId": "…", "login": {…}}`, or `"bound": {"path": "…", …}` in place of
`login` for a bound file, written on first load so the install id that
names the device to Anthropic stays the same from the first run on. Signing out of ChatGPT
removes its file; signing out of Claude keeps the install id.

## Tests

`cargo test` runs both accounts against stand-in auth servers on local ports: browser sign-ins
through their real callback, device-code polling, concurrent refreshes, refused refreshes, and
file permissions.
