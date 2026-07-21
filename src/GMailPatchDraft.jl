module GMailPatchDraft

using Base64: base64encode, base64decode
using HTTP
using JSON
using Random: RandomDevice
using SHA: sha256
using Sockets

const SERVICE = "gmail-patch-draft"
# The granular drafts-only scope (visible in the Cloud Console's scope list;
# the API reference still lags behind), plus gmail.send so `send` can transmit
# the message verbatim via messages.send — sending a draft from the Gmail UI
# regenerates the headers and re-wraps the body, losing In-Reply-To and
# mangling patches. Override with $GMAIL_SCOPE (space-separated); adding
# gmail.readonly additionally lets `draft` resolve the replied-to message's
# threadId (an rfc822msgid: search) so drafts thread in your own mailbox view.
const DEFAULT_SCOPE = "https://www.googleapis.com/auth/gmail.drafts.create " *
                      "https://www.googleapis.com/auth/gmail.send"
scope() = get(ENV, "GMAIL_SCOPE", DEFAULT_SCOPE)
const AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
const DRAFTS_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/drafts"
const MESSAGES_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/messages"

b64url(bytes) = String(rstrip(replace(base64encode(bytes), '+' => '-', '/' => '_'), '='))

# ---------------------------------------------------------------------------
# Credential storage: macOS Keychain, with a 0600-file fallback elsewhere.
# Only the long-lived refresh token (plus the OAuth client pair) is persisted;
# access tokens live in process memory and die with it.
# ---------------------------------------------------------------------------

keychain_account() = get(ENV, "USER", "default")
fallback_path() = joinpath(homedir(), ".config", SERVICE, "credentials.json")

function store_credentials(creds::AbstractDict)
    payload = JSON.json(creds)
    if Sys.isapple()
        run(pipeline(`security add-generic-password -U -a $(keychain_account()) -s $SERVICE
                      -j "OAuth refresh token for $SERVICE" -w $payload`;
                     stdout = devnull, stderr = devnull))
        println("Credentials stored in the macOS Keychain (service \"$SERVICE\").")
    else
        path = fallback_path()
        mkpath(dirname(path))
        touch(path)
        chmod(path, 0o600)
        write(path, payload)
        println("No macOS Keychain on this platform — credentials stored at $path (mode 0600).")
    end
end

function load_credentials()
    if Sys.isapple()
        out = IOBuffer()
        ok = success(pipeline(`security find-generic-password -a $(keychain_account()) -s $SERVICE -w`;
                              stdout = out, stderr = devnull))
        ok || return nothing
        return JSON.parse(String(take!(out)))
    else
        path = fallback_path()
        isfile(path) || return nothing
        return JSON.parse(read(path, String))
    end
end

function delete_credentials()
    if Sys.isapple()
        success(pipeline(`security delete-generic-password -a $(keychain_account()) -s $SERVICE`;
                         stdout = devnull, stderr = devnull))
    else
        rm(fallback_path(); force = true)
    end
    return nothing
end

# ---------------------------------------------------------------------------
# OAuth 2.0 installed-app flow (loopback redirect + PKCE)
# ---------------------------------------------------------------------------

function open_browser(url::String)
    cmd = Sys.isapple() ? `open $url` :
          Sys.iswindows() ? `cmd /c start "" $url` : `xdg-open $url`
    try
        run(pipeline(cmd; stdout = devnull, stderr = devnull); wait = false)
    catch
    end
    return nothing
end

html_response(msg) = HTTP.Response(200, ["Content-Type" => "text/html; charset=utf-8"],
    "<!doctype html><meta charset=\"utf-8\"><title>$SERVICE</title><p style=\"font: 16px system-ui; margin: 3em\">$msg</p>")

function token_post(params)::Tuple{Int,String}
    resp = HTTP.post(TOKEN_ENDPOINT,
        ["Content-Type" => "application/x-www-form-urlencoded"],
        HTTP.escapeuri(params); status_exception = false)
    return resp.status, String(resp.body)
end

"""
Run the OAuth authorization-code flow and return a refresh token.
Uses a loopback redirect on an ephemeral 127.0.0.1 port and PKCE (S256).
"""
function oauth_authorize(client_id::String, client_secret::String)
    rng = RandomDevice()
    verifier = b64url(rand(rng, UInt8, 32))
    challenge = b64url(sha256(verifier))
    state = b64url(rand(rng, UInt8, 16))

    port, tcpserver = listenany(Sockets.localhost, 0)
    redirect_uri = "http://127.0.0.1:$(Int(port))/"

    outcome = Channel{Any}(4)
    server = HTTP.serve!(Sockets.localhost, Int(port); server = tcpserver, verbose = -1) do req
        q = HTTP.queryparams(HTTP.URI(req.target))
        if haskey(q, "error")
            put!(outcome, ErrorException("authorization failed: $(q["error"])"))
            html_response("Authorization failed: $(q["error"]). You can close this tab.")
        elseif haskey(q, "code") && get(q, "state", "") == state
            put!(outcome, q["code"])
            html_response("Authorized ✓ — you can close this tab and return to the terminal.")
        else
            # favicon requests, stale tabs, state mismatches: keep waiting
            HTTP.Response(404, "Waiting for the OAuth redirect…")
        end
    end

    auth_url = AUTH_ENDPOINT * "?" * HTTP.escapeuri(Dict(
        "client_id" => client_id,
        "redirect_uri" => redirect_uri,
        "response_type" => "code",
        "scope" => scope(),
        "access_type" => "offline",
        "prompt" => "consent",
        "state" => state,
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
    ))

    println("Complete the authorization in your browser. If it doesn't open automatically, visit:\n")
    println("    $auth_url\n")
    open_browser(auth_url)

    code = try
        result = take!(outcome)
        result isa Exception && throw(result)
        result::String
    finally
        close(server)
    end

    status, body = token_post(Dict(
        "client_id" => client_id,
        "client_secret" => client_secret,
        "code" => code,
        "code_verifier" => verifier,
        "grant_type" => "authorization_code",
        "redirect_uri" => redirect_uri,
    ))
    status == 200 || error("token exchange failed (HTTP $status): $body")
    tok = JSON.parse(body)
    haskey(tok, "refresh_token") || error(
        "Google returned no refresh_token. Revoke the app's access at " *
        "https://myaccount.google.com/permissions and re-run `$SERVICE auth`.")
    return String(tok["refresh_token"]), String(get(tok, "scope", scope()))
end

"Exchange the stored refresh token for a short-lived access token (kept in memory only)."
function fetch_access_token(creds)
    status, body = token_post(Dict(
        "client_id" => creds["client_id"],
        "client_secret" => creds["client_secret"],
        "refresh_token" => creds["refresh_token"],
        "grant_type" => "refresh_token",
    ))
    status == 200 || error("access-token refresh failed (HTTP $status): $body\n" *
                           "If the grant was revoked or expired, re-run `$SERVICE auth`.")
    return String(JSON.parse(body)["access_token"])
end

# ---------------------------------------------------------------------------
# git format-patch → RFC 822 → Gmail draft
# ---------------------------------------------------------------------------

# RFC 2047 encoded-word (B encoding), chunked so each word stays ≤75 chars
# ("=?UTF-8?B?" + base64 of ≤45 raw bytes + "?="), split at UTF-8 boundaries.
function encoded_word(s::AbstractString)
    words = String[]
    buf = IOBuffer()
    for c in s
        if position(buf) + ncodeunits(c) > 45
            push!(words, "=?UTF-8?B?$(base64encode(take!(buf)))?=")
        end
        print(buf, c)
    end
    position(buf) > 0 && push!(words, "=?UTF-8?B?$(base64encode(take!(buf)))?=")
    return join(words, " ")
end

"""
Format one `--to`/`--cc` argument as an RFC 822 address. Headers are 7-bit, so
a non-ASCII display name ("André Almeida <a@b.c>") must become an RFC 2047
encoded-word — pasting raw UTF-8 into the header shows up as mojibake. ASCII
names containing specials (e.g. "Almeida, André"'s comma, which would read as
an address-list separator) are quoted instead.
"""
function format_address(addr::AbstractString)
    m = match(r"^\s*(.*?)\s*<([^<>]+)>\s*$", addr)
    m === nothing && return String(strip(addr))  # bare address
    name, email = String(m.captures[1]), m.captures[2]
    isempty(name) && return "<$email>"
    if !isascii(name)
        name = encoded_word(name)
    elseif occursin(r"[^A-Za-z0-9 !#$%&'*+\-/=?^_`{|}~]", name) && !startswith(name, '"')
        name = "\"" * replace(name, "\\" => "\\\\", "\"" => "\\\"") * "\""
    end
    return "$name <$email>"
end

# Split a header block into logical headers, keeping the original (possibly
# folded) text alongside the unfolded single-line value.
function unfold_headers(hdr::AbstractString)
    logical = Tuple{String,String}[]
    lines = split(hdr, '\n')
    i = 1
    while i <= length(lines)
        orig = IOBuffer(); unfolded = IOBuffer()
        print(orig, lines[i]); print(unfolded, lines[i])
        i += 1
        while i <= length(lines) && startswith(lines[i], r"[ \t]")
            print(orig, '\n', lines[i])
            print(unfolded, ' ', strip(lines[i]))
            i += 1
        end
        push!(logical, (String(take!(orig)), String(take!(unfolded))))
    end
    return logical
end

# Split an address list on commas, ignoring commas inside quoted strings
# ("Almeida, Andre" <a@b.c>).
function split_addresses(s::AbstractString)
    parts = String[]
    buf = IOBuffer()
    inquote = escaped = false
    for c in s
        if escaped
            print(buf, c); escaped = false
        elseif c == '\\' && inquote
            print(buf, c); escaped = true
        elseif c == '"'
            print(buf, c); inquote = !inquote
        elseif c == ',' && !inquote
            p = strip(String(take!(buf)))
            isempty(p) || push!(parts, p)
        else
            print(buf, c)
        end
    end
    p = strip(String(take!(buf)))
    isempty(p) || push!(parts, p)
    return parts
end

"""
Turn `git format-patch` output into an RFC 822 message for Gmail.

format-patch already emits a valid message (From/Date/Subject headers + body),
so the body passes through verbatim. In the headers we strip the leading mbox
separator (`From <sha> Mon Sep 17 00:00:00 2001` — distinguishable from a real
header because it has no colon) and rebuild the To:/Cc: headers: format-patch
writes `--to`/`--cc` recipients into the patch verbatim and leaves the RFC 2047
encoding of non-ASCII names to `git send-email`, so since we replace
send-email here, that re-encoding (via [`format_address`](@ref)) is our job.
CLI-provided recipients are merged into the same headers.
"""
function patch_to_rfc822(raw::AbstractString; to = String[], cc = String[])
    if startswith(raw, "From ")
        nl = findfirst('\n', raw)
        raw = nl === nothing ? "" : SubString(raw, nl + 1)
    end
    sep = findfirst("\n\n", raw)
    hdr = sep === nothing ? String(raw) : String(SubString(raw, 1, first(sep) - 1))
    body = sep === nothing ? "" : String(SubString(raw, last(sep) + 1))

    to_list = String[]; cc_list = String[]; kept = String[]
    for (orig, unfolded) in unfold_headers(hdr)
        m = match(r"^(To|Cc):\s*(.*)$"i, unfolded)
        if m !== nothing
            dest = lowercase(m.captures[1]) == "to" ? to_list : cc_list
            append!(dest, split_addresses(m.captures[2]))
        else
            push!(kept, orig)
        end
    end
    append!(to_list, to)
    append!(cc_list, cc)

    io = IOBuffer()
    for h in kept
        println(io, h)
    end
    isempty(to_list) || println(io, "To: ", join(unique(map(format_address, to_list)), ",\n    "))
    isempty(cc_list) || println(io, "Cc: ", join(unique(map(format_address, cc_list)), ",\n    "))
    print(io, '\n', body)
    return String(take!(io))
end

# The Message-ID this message replies to (In-Reply-To, falling back to the
# last References entry), or nothing.
function reply_target_msgid(rfc822::AbstractString)
    sep = findfirst("\n\n", rfc822)
    hdr = sep === nothing ? rfc822 : SubString(rfc822, 1, first(sep) - 1)
    refs = nothing
    for (_, unfolded) in unfold_headers(hdr)
        m = match(r"^In-Reply-To:\s*(<[^<>]+>)"i, unfolded)
        m === nothing || return String(m.captures[1])
        m = match(r"^References:\s*(.*)$"i, unfolded)
        m === nothing || (refs = m.captures[1])
    end
    refs === nothing && return nothing
    m = collect(eachmatch(r"<[^<>]+>", refs))
    return isempty(m) ? nothing : String(m[end].match)
end

"""
Find the Gmail threadId of the message with the given RFC 822 Message-ID via
an `rfc822msgid:` search. Gmail threads a draft only if the draft resource
carries the threadId — In-Reply-To/References in the raw message are ignored
for the mailbox's own threading (they still matter for the recipients).
Returns nothing (with a warning) if the search is not permitted by the token's
scope or the message isn't in the mailbox.
"""
function lookup_thread_id(access_token::String, msgid::AbstractString)
    query = HTTP.escapeuri(Dict("q" => "rfc822msgid:" * strip(msgid, ['<', '>']),
                                "maxResults" => "1"))
    resp = HTTP.get(MESSAGES_ENDPOINT * "?" * query,
                    ["Authorization" => "Bearer $access_token"]; status_exception = false)
    if resp.status == 403
        @warn "token's scope does not permit searching for the replied-to message; " *
              "creating the draft unthreaded (re-run `$SERVICE auth` with " *
              "\$GMAIL_SCOPE including gmail.readonly to enable this)"
        return nothing
    elseif resp.status != 200
        @warn "rfc822msgid search failed (HTTP $(resp.status)); creating the draft unthreaded"
        return nothing
    end
    msgs = get(JSON.parse(String(resp.body)), "messages", [])
    if isempty(msgs)
        @warn "replied-to message $msgid not found in this mailbox; creating the draft unthreaded"
        return nothing
    end
    return String(msgs[1]["threadId"])
end

# Search (for the threadId lookup) needs a read-capable scope; we record the
# granted scopes at auth time. Credentials from older versions lack "scope".
can_search(creds) = occursin(r"gmail\.readonly|gmail\.modify|mail\.google\.com",
                             get(creds, "scope", ""))

function create_draft(access_token::String, rfc822::String; thread_id = nothing)
    message = Dict{String,Any}("raw" => b64url(codeunits(rfc822)))
    thread_id === nothing || (message["threadId"] = thread_id)
    resp = HTTP.post(DRAFTS_ENDPOINT,
        ["Authorization" => "Bearer $access_token",
         "Content-Type" => "application/json"],
        JSON.json(Dict("message" => message)); status_exception = false)
    resp.status == 200 || error("drafts.create failed (HTTP $(resp.status)): $(String(resp.body))")
    return JSON.parse(String(resp.body))
end

"""
Send the message verbatim via messages.send (scope: gmail.send). Unlike
sending a draft from the Gmail UI — which regenerates headers (dropping
In-Reply-To/References) and re-wraps the body — this transmits the RFC 822
message byte-for-byte, so threading headers reach the recipients and patches
survive `git am`.
"""
function send_message(access_token::String, rfc822::String)
    resp = HTTP.post(MESSAGES_ENDPOINT * "/send",
        ["Authorization" => "Bearer $access_token",
         "Content-Type" => "application/json"],
        JSON.json(Dict("raw" => b64url(codeunits(rfc822)))); status_exception = false)
    resp.status == 200 || error("messages.send failed (HTTP $(resp.status)): $(String(resp.body))")
    return JSON.parse(String(resp.body))
end

# ---------------------------------------------------------------------------
# lore.kernel.org → reply-all template
# ---------------------------------------------------------------------------

function qp_decode(s::AbstractString)
    s = replace(s, r"=\r?\n" => "")  # soft line breaks
    bytes = codeunits(s)
    io = IOBuffer()
    i = 1
    while i <= length(bytes)
        if bytes[i] == UInt8('=') && i + 2 <= length(bytes) &&
           all(c -> c in '0':'9' || c in 'A':'F' || c in 'a':'f', Char.(bytes[i+1:i+2]))
            write(io, parse(UInt8, String(bytes[i+1:i+2]); base = 16))
            i += 3
        else
            write(io, bytes[i])
            i += 1
        end
    end
    return String(take!(io))
end

# Decode RFC 2047 encoded-words for display (attribution line). Only UTF-8 /
# US-ASCII charsets are decoded; anything else is left as-is.
function decode_rfc2047(s::AbstractString)
    s = replace(s, r"\?=\s+=\?" => "?==?")  # whitespace between adjacent words is ignored
    return replace(s, r"=\?[^?]+\?[BbQq]\?[^?]*\?=" => function (w)
        m = match(r"^=\?([^?]+)\?([BbQq])\?([^?]*)\?=$", w)
        charset, enc, txt = lowercase(m.captures[1]), uppercase(m.captures[2]), m.captures[3]
        startswith(charset, "utf-8") || startswith(charset, "us-ascii") || return w
        return enc == "B" ? String(base64decode(txt)) : qp_decode(replace(txt, "_" => " "))
    end)
end

addr_spec(a::AbstractString) =
    (m = match(r"<([^<>]+)>", a); lowercase(strip(m === nothing ? a : m.captures[1])))

function unique_by_spec(addrs)
    seen = Set{String}()
    return filter(a -> !in(addr_spec(a), seen) && (push!(seen, addr_spec(a)); true), addrs)
end

"""
Build a reply-all template (an editable RFC 822 message) from a raw message as
served by `https://lore.kernel.org/<list>/<msgid>/raw`. Threading is preserved
via In-Reply-To/References (plus the matching `Re:` subject), which is what
both Gmail and the recipients' clients use to place the reply in the thread.
To: is the author being replied to; the original To/Cc recipients move to Cc.
`my_email` (typically `git config user.email`) is dropped from the recipients.
"""
function build_reply(msg::AbstractString; my_email::AbstractString = "")
    if startswith(msg, "From ")
        nl = findfirst('\n', msg)
        msg = nl === nothing ? "" : SubString(msg, nl + 1)
    end
    sep = findfirst("\n\n", msg)
    hdr = sep === nothing ? String(msg) : String(SubString(msg, 1, first(sep) - 1))
    body = sep === nothing ? "" : String(SubString(msg, last(sep) + 1))

    headers = Dict{String,String}()
    for (_, unfolded) in unfold_headers(hdr)
        m = match(r"^([!-9;-~]+):\s*(.*)$", unfolded)
        m === nothing || (headers[lowercase(m.captures[1])] = m.captures[2])
    end

    msgid = String(strip(get(headers, "message-id", "")))
    isempty(msgid) && error("message has no Message-ID header — cannot thread a reply")

    subject = get(headers, "subject", "")
    occursin(r"^\s*Re:"i, subject) || (subject = "Re: " * subject)

    # reply-all: To = the author (Reply-To, or From), everyone else from the
    # original To + Cc goes to Cc, minus ourselves and duplicates
    sender = get(headers, "reply-to", get(headers, "from", ""))
    notme(a) = isempty(my_email) || addr_spec(a) != lowercase(strip(my_email))
    to = unique_by_spec(filter(notme, split_addresses(sender)))
    to_specs = Set(addr_spec.(to))
    cc = unique_by_spec(filter(a -> notme(a) && !in(addr_spec(a), to_specs),
                               [split_addresses(get(headers, "to", ""));
                                split_addresses(get(headers, "cc", ""))]))

    refs = String.(split(get(headers, "references", "")))
    push!(refs, msgid)

    # body: undo transfer encoding and mboxrd From-escaping, then quote
    cte = lowercase(strip(get(headers, "content-transfer-encoding", "")))
    if cte == "base64"
        body = String(base64decode(filter(!isspace, body)))
    elseif cte == "quoted-printable"
        body = qp_decode(body)
    end
    startswith(lowercase(get(headers, "content-type", "")), "multipart/") &&
        @warn "original message is multipart; quoting the raw body"
    body = replace(body, r"^>(>*From )"m => s"\1")
    quoted = join((isempty(l) ? ">" : startswith(l, ">") ? ">" * l : "> " * l
                   for l in split(chomp(body), '\n')), '\n')

    io = IOBuffer()
    isempty(to) || println(io, "To: ", join(to, ",\n    "))
    isempty(cc) || println(io, "Cc: ", join(cc, ",\n    "))
    println(io, "Subject: ", subject)
    println(io, "In-Reply-To: ", msgid)
    println(io, "References: ", join(refs, "\n    "))
    println(io)
    println(io, "On ", get(headers, "date", "an unknown date"), ", ",
            decode_rfc2047(sender), " wrote:")
    println(io, quoted)
    return String(take!(io)), msgid
end

function cmd_reply(args::Vector{String})
    url = outpath = nothing
    i = 1
    while i <= length(args)
        a = args[i]
        if a in ("-o", "--output")
            i == length(args) && error("$a requires a value")
            outpath = args[i+1]; i += 2
        elseif startswith(a, "-") && a != "-"
            error("unknown option for reply: $a")
        elseif url === nothing
            url = a; i += 1
        else
            error("reply takes a single URL")
        end
    end
    url === nothing && error("no lore URL given")

    rawurl = endswith(url, "/raw") ? url :
             endswith(url, "/")    ? url * "raw" : url * "/raw"
    resp = HTTP.get(rawurl; status_exception = false)
    resp.status == 200 || error("fetching $rawurl failed (HTTP $(resp.status))")

    my_email = try
        strip(read(`git config user.email`, String))
    catch
        ""
    end
    reply, msgid = build_reply(String(resp.body); my_email)

    if outpath === nothing
        outpath = "reply-" * replace(strip(msgid, ['<', '>']), r"[^A-Za-z0-9._@-]" => "-") * ".txt"
    end
    outpath != "-" && isfile(outpath) &&
        error("$outpath already exists — pass -o to choose another name")
    if outpath == "-"
        print(reply)
    else
        write(outpath, reply)
        println("Reply template written to $outpath")
        println("Edit it, then create the draft with: $SERVICE draft $outpath")
    end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

function print_usage(io::IO = stdout)
    print(io, """
        $SERVICE — file git format-patch output as Gmail drafts

        Usage:
          $SERVICE auth [--client-id ID] [--client-secret SECRET]
              Authorize via OAuth (browser flow, PKCE) and store the refresh
              token in the macOS Keychain. Falls back to \$GMAIL_CLIENT_ID /
              \$GMAIL_CLIENT_SECRET, then to interactive prompts.

          $SERVICE draft [--to ADDR]... [--cc ADDR]... PATCH...
              Create one Gmail draft per .patch file ("-" reads stdin).

          $SERVICE send [--to ADDR]... [--cc ADDR]... PATCH...
              Send the message(s) verbatim via messages.send. Unlike the Gmail
              UI's Send button, this preserves In-Reply-To/References and does
              not re-wrap the patch.

          $SERVICE reply LORE_URL [-o FILE]
              Fetch a message from lore.kernel.org and write an editable
              reply-all template ("-o -" prints to stdout). In-Reply-To and
              References are set from the Message-ID, so `draft`ing the edited
              file threads the reply correctly.

          $SERVICE logout
              Delete the stored credentials.

        Requires a Google Cloud OAuth client of type "Desktop app" with the
        Gmail API enabled (scopes: gmail.drafts.create + gmail.send,
        overridable via \$GMAIL_SCOPE). See the README.
        """)
end

function cmd_auth(args::Vector{String})
    client_id = client_secret = nothing
    i = 1
    while i <= length(args)
        if args[i] == "--client-id" && i < length(args)
            client_id = args[i+1]; i += 2
        elseif args[i] == "--client-secret" && i < length(args)
            client_secret = args[i+1]; i += 2
        else
            error("unknown or incomplete option for auth: $(args[i])")
        end
    end
    if client_id === nothing
        client_id = get(ENV, "GMAIL_CLIENT_ID", "")
        isempty(client_id) && (client_id = something(Base.prompt("OAuth client ID"), ""))
        isempty(client_id) && error("an OAuth client ID is required")
    end
    if client_secret === nothing
        client_secret = get(ENV, "GMAIL_CLIENT_SECRET", "")
        if isempty(client_secret)
            sb = Base.getpass("OAuth client secret")
            client_secret = read(sb, String)
            Base.shred!(sb)
        end
        isempty(client_secret) && error("an OAuth client secret is required")
    end
    refresh_token, granted_scope = oauth_authorize(String(client_id), String(client_secret))
    store_credentials(Dict(
        "client_id" => client_id,
        "client_secret" => client_secret,
        "refresh_token" => refresh_token,
        "scope" => granted_scope,
    ))
    println("Done. Try: $SERVICE draft --to someone@example.com 0001-*.patch")
end

function parse_recipient_args(cmd::String, args::Vector{String})
    to = String[]; cc = String[]; files = String[]
    i = 1
    while i <= length(args)
        a = args[i]
        if a in ("--to", "--cc")
            i == length(args) && error("$a requires a value")
            push!(a == "--to" ? to : cc, args[i+1])
            i += 2
        elseif startswith(a, "--")
            error("unknown option for $cmd: $a")
        else
            push!(files, a)
            i += 1
        end
    end
    isempty(files) && error("no patch files given (use \"-\" for stdin)")
    for f in files
        f == "-" || isfile(f) || error("no such file: $f")
    end
    return to, cc, files
end

function authorized_token()
    creds = load_credentials()
    creds === nothing && error("no stored credentials — run `$SERVICE auth` first")
    return creds, fetch_access_token(creds)
end

function cmd_draft(args::Vector{String})
    to, cc, files = parse_recipient_args("draft", args)
    creds, access_token = authorized_token()
    for f in files
        raw = f == "-" ? read(stdin, String) : read(f, String)
        rfc822 = patch_to_rfc822(raw; to, cc)
        msgid = reply_target_msgid(rfc822)
        thread_id = msgid !== nothing && can_search(creds) ?
                    lookup_thread_id(access_token, msgid) : nothing
        draft = create_draft(access_token, rfc822; thread_id)
        threaded = thread_id === nothing ? "" : " (threaded into $thread_id)"
        println("created draft $(draft["id"]) from $(f == "-" ? "<stdin>" : f)$threaded")
        msgid === nothing || thread_id !== nothing ||
            println("  note: reply drafts don't thread in the Gmail UI without a read " *
                    "scope, and sending from the UI drops In-Reply-To — use `$SERVICE send`.")
    end
    println("Review at https://mail.google.com/mail/#drafts, then send with `$SERVICE send`.")
end

function cmd_send(args::Vector{String})
    to, cc, files = parse_recipient_args("send", args)
    _, access_token = authorized_token()
    for f in files
        raw = f == "-" ? read(stdin, String) : read(f, String)
        sent = send_message(access_token, patch_to_rfc822(raw; to, cc))
        println("sent $(sent["id"]) from $(f == "-" ? "<stdin>" : f)")
    end
end

function (@main)(args)
    if isempty(args)
        print_usage(stderr)
        return 2
    end
    cmd, rest = args[1], collect(String, args[2:end])
    try
        if cmd in ("help", "-h", "--help")
            print_usage()
        elseif cmd == "auth"
            cmd_auth(rest)
        elseif cmd == "draft"
            cmd_draft(rest)
        elseif cmd == "send"
            cmd_send(rest)
        elseif cmd == "reply"
            cmd_reply(rest)
        elseif cmd == "logout"
            delete_credentials()
            println("Stored credentials deleted.")
        else
            println(stderr, "unknown command: $cmd\n")
            print_usage(stderr)
            return 2
        end
    catch err
        err isa InterruptException && rethrow()
        println(stderr, "error: ", sprint(showerror, err))
        return 1
    end
    return 0
end

end # module GMailPatchDraft
