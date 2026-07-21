module GMailPatchDraft

using Base64: base64encode
using HTTP
using JSON
using Random: RandomDevice
using SHA: sha256
using Sockets

const SERVICE = "gmail-patch-draft"
# The granular drafts-only scope (visible in the Cloud Console's scope list;
# the API reference still lags behind). Override with $GMAIL_SCOPE — e.g. set it
# to .../auth/gmail.compose for projects where the granular scope isn't offered.
const DEFAULT_SCOPE = "https://www.googleapis.com/auth/gmail.drafts.create"
scope() = get(ENV, "GMAIL_SCOPE", DEFAULT_SCOPE)
const AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
# Media upload avoids double base64: the RFC 822 message is the request body.
const DRAFT_UPLOAD_ENDPOINT = "https://gmail.googleapis.com/upload/gmail/v1/users/me/drafts?uploadType=media"

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
    return String(tok["refresh_token"])
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

"""
Turn `git format-patch` output into an RFC 822 message for Gmail.

format-patch already emits a valid message (From/Date/Subject headers + body);
we only strip the leading mbox separator (`From <sha> Mon Sep 17 00:00:00 2001`)
— distinguishable from a real header because it has no colon — and prepend
optional To/Cc headers.
"""
function patch_to_rfc822(raw::AbstractString; to = String[], cc = String[])
    if startswith(raw, "From ")
        nl = findfirst('\n', raw)
        raw = nl === nothing ? "" : SubString(raw, nl + 1)
    end
    io = IOBuffer()
    isempty(to) || println(io, "To: ", join(map(format_address, to), ", "))
    isempty(cc) || println(io, "Cc: ", join(map(format_address, cc), ", "))
    write(io, raw)
    return String(take!(io))
end

function create_draft(access_token::String, rfc822::String)
    resp = HTTP.post(DRAFT_UPLOAD_ENDPOINT,
        ["Authorization" => "Bearer $access_token",
         "Content-Type" => "message/rfc822"],
        rfc822; status_exception = false)
    resp.status == 200 || error("drafts.create failed (HTTP $(resp.status)): $(String(resp.body))")
    return JSON.parse(String(resp.body))
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

          $SERVICE logout
              Delete the stored credentials.

        Requires a Google Cloud OAuth client of type "Desktop app" with the
        Gmail API enabled (scope: gmail.drafts.create, overridable via
        \$GMAIL_SCOPE). See the README for setup.
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
    refresh_token = oauth_authorize(String(client_id), String(client_secret))
    store_credentials(Dict(
        "client_id" => client_id,
        "client_secret" => client_secret,
        "refresh_token" => refresh_token,
    ))
    println("Done. Try: $SERVICE draft --to someone@example.com 0001-*.patch")
end

function cmd_draft(args::Vector{String})
    to = String[]; cc = String[]; files = String[]
    i = 1
    while i <= length(args)
        a = args[i]
        if a in ("--to", "--cc")
            i == length(args) && error("$a requires a value")
            push!(a == "--to" ? to : cc, args[i+1])
            i += 2
        elseif startswith(a, "--")
            error("unknown option for draft: $a")
        else
            push!(files, a)
            i += 1
        end
    end
    isempty(files) && error("no patch files given (use \"-\" for stdin)")
    for f in files
        f == "-" || isfile(f) || error("no such file: $f")
    end

    creds = load_credentials()
    creds === nothing && error("no stored credentials — run `$SERVICE auth` first")
    access_token = fetch_access_token(creds)

    for f in files
        raw = f == "-" ? read(stdin, String) : read(f, String)
        draft = create_draft(access_token, patch_to_rfc822(raw; to, cc))
        println("created draft $(draft["id"]) from $(f == "-" ? "<stdin>" : f)")
    end
    println("Review and send: https://mail.google.com/mail/#drafts")
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
