# GMailPatchDraft

A Julia app (per the [Julia 1.12 Apps spec](https://pkgdocs.julialang.org/v1/apps/))
that files `git format-patch` output as Gmail drafts via the
`gmail.users.drafts.create` OAuth API. On macOS the long-lived OAuth refresh
token is kept in the Keychain; short-lived access tokens exist only in process
memory.

Uses `HTTP.jl` for the API calls and the OAuth loopback listener, and `JSON.jl`
for the API responses; everything else is stdlib.

## One-time Google setup

1. In the [Google Cloud Console](https://console.cloud.google.com/), create (or
   pick) a project and **enable the Gmail API**.
2. Configure the OAuth consent screen (audience "External" is fine; add your
   own address as a test user).
3. Create credentials → **OAuth client ID** → application type **Desktop app**.
   Note the client ID and client secret. (For installed apps the "secret" is
   not actually confidential; PKCE is used regardless.)

Two scopes are requested by default:

- `https://www.googleapis.com/auth/gmail.drafts.create` — the granular
  drafts-only scope. It appears in the Cloud Console's scope list even though
  the Gmail API reference docs still lag behind.
- `https://www.googleapis.com/auth/gmail.send` — for the `send` subcommand.
  This exists because the Gmail UI's Send button re-serializes the draft on
  send — hard-wrapping lines, converting tabs, regenerating headers — even
  when the draft is attached to the right thread, which corrupts patches and
  strips reply threading for recipients. `send` transmits the RFC 822 message
  byte-for-byte via `messages.send` instead. Neither scope can read mail.

Set `GMAIL_SCOPE` (space-separated) before `auth` to override — e.g. only
`gmail.drafts.create` for a draft-only token, or `gmail.compose` for projects
where the granular scopes aren't offered.

## Install

```
julia -e 'using Pkg; Pkg.Apps.add(path="/path/to/GMailPatchDraft")'
```

(or `pkg> app add /path/to/GMailPatchDraft` from the Pkg REPL). Note that
`app add` with a path expects a git repository; for a plain checkout use
`Pkg.Apps.develop(path=...)` instead. Make sure
`~/.julia/bin` is on your `PATH`. Alternatively, run without installing:

```
julia --project=/path/to/GMailPatchDraft -m GMailPatchDraft <args>
```

## Use

```sh
# Authorize once: opens a browser, catches the redirect on 127.0.0.1,
# stores the refresh token in the Keychain (service "gmail-patch-draft").
gmail-patch-draft auth --client-id 1234-abc.apps.googleusercontent.com
# (client secret is prompted for with hidden input, or use --client-secret /
#  $GMAIL_CLIENT_ID / $GMAIL_CLIENT_SECRET)

# File patches as drafts:
git format-patch -1 HEAD
gmail-patch-draft draft --to reviewer@example.com --cc list@example.com 0001-*.patch

# Or straight from stdin:
git format-patch --stdout -1 HEAD | gmail-patch-draft draft --to reviewer@example.com -

# Reply-all to a list message: fetch it from lore.kernel.org, edit the
# generated template, then draft it. In-Reply-To/References are set from the
# original Message-ID, so the draft threads correctly. To: is the author being
# replied to, everyone else moves to Cc:, and your own address
# (git config user.email) is dropped.
gmail-patch-draft reply https://lore.kernel.org/lkml/87bjc0led9.ffs@fw13/
$EDITOR reply-87bjc0led9.ffs@fw13.txt
gmail-patch-draft draft --thread-id FMfcgzQhVWwLZMnDwNWCdxPKKSXRLgKp reply-87bjc0led9.ffs@fw13.txt

# After reviewing the draft in Gmail, send the same file verbatim via the
# API — do NOT use the UI's Send button, which re-wraps lines and drops the
# threading headers (discard the review draft afterwards):
gmail-patch-draft send --thread-id FMfcgzQhVWwLZMnDwNWCdxPKKSXRLgKp reply-87bjc0led9.ffs@fw13.txt

# Forget the stored credentials:
gmail-patch-draft logout
```

Each patch becomes one draft; `format-patch` output is already RFC 822, so
the app strips the leading mbox `From <sha> …` separator and merges
`--to`/`--cc` into any `To:`/`Cc:` headers already in the patch. Non-ASCII
recipient names are RFC 2047-encoded — `format-patch` writes `--to`/`--cc`
recipients verbatim and normally leaves that to `git send-email`, whose role
this app takes over. The body passes through byte-for-byte, so attribution,
date, and subject survive untouched and `git am` on the receiving end still
applies cleanly.

## Reply threading and `--thread-id`

Gmail associates a draft with a conversation **only** via the `threadId` on
the draft resource — the `In-Reply-To`/`References` headers in the uploaded
message are not used for this, and when a draft without a `threadId` is sent
from the Gmail UI, the composer regenerates the headers and those headers are
silently dropped (recipients get an unthreaded mail). Resolving a `threadId`
by Message-ID requires a read scope this tool deliberately doesn't request,
so for replies pass it manually:

```
gmail-patch-draft draft --thread-id ID reply-….txt
```

`ID` accepts any of:

- the token in the Gmail web UI's URL bar while viewing the thread
  (`#inbox/FMfcgzQhVWwLZMnDwNWCdxPKKSXRLgKp`) — easiest. It's a base-40
  encoding of `thread-f:<decimal>` (scheme reverse-engineered by
  [Arsenal Recon's GmailURLDecoder](https://github.com/ArsenalRecon/GmailURLDecoder))
  and is decoded locally. Threads whose token decodes to an `a:` id (threads
  you started from the new Gmail composer) have no hex API id — use the
  `msg-f:` form of a *received* message in the thread instead;
- `msg-f:<decimal>` / `thread-f:<decimal>` from the UI's "Show original" view
  of the thread's **first** message (`permmsgid=msg-f:<decimal>` in its URL —
  a thread's id equals its first message's id);
- the hex API threadId itself.

Attaching the draft to the thread makes the review copy appear in the right
conversation. **Don't send it from the UI though**: the Send button
re-serializes the draft even when it's correctly threaded — lines get
hard-wrapped (corrupting patches for `git am`) and the threading headers are
regenerated rather than preserved. Send the same file with
`gmail-patch-draft send` instead, which transmits it byte-for-byte; pass the
same `--thread-id` so the sent copy lands in the conversation in your own
mailbox too (recipients thread by the In-Reply-To/References headers either
way). The draft is a review copy — discard it after sending.

## Security notes

- **Persisted:** only the refresh token + OAuth client pair, as a generic
  password in the macOS Keychain (`security add-generic-password -s
  gmail-patch-draft`). On non-macOS platforms it falls back to
  `~/.config/gmail-patch-draft/credentials.json` with mode `0600`.
- **Ephemeral:** access tokens are fetched per invocation via the refresh
  grant and never written to disk.
- The Keychain write passes the secret as an argument to `/usr/bin/security`,
  so it is briefly visible in the process table to other processes of the same
  user — the standard tradeoff for CLI Keychain use.
- OAuth uses the loopback-redirect flow with PKCE (S256) and a `state` check.
- To revoke everything: `gmail-patch-draft logout`, then remove the app at
  <https://myaccount.google.com/permissions>.
