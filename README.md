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

The requested scope is `https://www.googleapis.com/auth/gmail.drafts.create` —
the granular drafts-only scope (it cannot send or read mail). It appears in
the Cloud Console's scope list even though the Gmail API reference docs still
lag behind. If your project doesn't offer it, set
`GMAIL_SCOPE=https://www.googleapis.com/auth/gmail.compose` before running
`auth` to fall back to the older scope.

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
gmail-patch-draft draft --thread-id msg-f:1636245846315289078 reply-87bjc0led9.ffs@fw13.txt

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

`ID` is either the hex API threadId, or `msg-f:<decimal>` / `thread-f:<decimal>`
as found in the Gmail UI: open the **first** message of the thread →
⋮ → "Show original" — the URL contains `permmsgid=msg-f:<decimal>` (a thread's
id equals its first message's id). With the draft attached to the thread, the
UI composer treats it as a reply to that conversation and generates correct
threading headers itself at send time.

One caveat for patches (as opposed to prose replies): the UI's Send button
also re-wraps long lines and converts tabs, which corrupts a patch for
`git am`. Prefer sending patch mails with a client that transmits the draft
verbatim.

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
