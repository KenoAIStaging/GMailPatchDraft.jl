using GMailPatchDraft: b64url, build_reply, decode_rfc2047, format_address,
                       normalize_thread_id, patch_to_rfc822, qp_decode
using Base64: base64decode, base64encode
using Test

@testset "decoding" begin
    @test qp_decode("Andr=C3=A9 says =3D hi=\nthere") == "André says = hithere"
    @test qp_decode("plain text") == "plain text"
    @test decode_rfc2047("=?UTF-8?B?QW5kcsOp?= Almeida") == "André Almeida"
    @test decode_rfc2047("=?utf-8?q?Andr=C3=A9_Almeida?=") == "André Almeida"
    @test decode_rfc2047("=?iso-2022-jp?B?abc?=") == "=?iso-2022-jp?B?abc?="  # unknown charset kept
    @test decode_rfc2047("no encoded words") == "no encoded words"
end

@testset "normalize_thread_id" begin
    @test normalize_thread_id("16b3a1b2c3d4e5f6") == "16b3a1b2c3d4e5f6"
    # decimal forms from the Gmail UI's "Show original" URL convert to hex
    @test normalize_thread_id("msg-f:1636245846315289078") ==
          string(UInt64(1636245846315289078); base = 16)
    @test normalize_thread_id("thread-f:1636245846315289078") ==
          string(UInt64(1636245846315289078); base = 16)
end

@testset "build_reply" begin
    msg = """
        From mboxrd@z Thu Jan  1 00:00:00 1970
        From: Thomas Gleixner <tglx@kernel.org>
        To: Keno Fischer <keno@juliahub.com>,
            =?UTF-8?B?QW5kcsOpIEFsbWVpZGE=?= <andrealmeid@igalia.com>
        Cc: linux-kernel@vger.kernel.org,
            Keno Fischer <keno@juliahub.com>
        Subject: [PATCH] futex: Prevent robust futex exit race more
        Date: Tue, 21 Jul 2026 00:31:48 +0000
        Message-ID: <87bjc0led9.ffs@fw13>
        References: <cover.123.git.keno@juliahub.com>
        Content-Type: text/plain; charset=utf-8

        Looks good to me.

        >From my side, no objections.
        """
    reply, msgid = build_reply(msg; my_email = "keno@juliahub.com")
    @test msgid == "<87bjc0led9.ffs@fw13>"
    hdr, body = split(reply, "\n\n"; limit = 2)
    # only the author goes to To:; original To/Cc recipients move to Cc:,
    # we are dropped everywhere, and To-members are not duplicated in Cc
    @test occursin("To: Thomas Gleixner <tglx@kernel.org>\n", hdr)
    @test occursin("Cc: =?UTF-8?B?QW5kcsOpIEFsbWVpZGE=?= <andrealmeid@igalia.com>,\n    linux-kernel@vger.kernel.org", hdr)
    recipients = split(hdr, "\nSubject:")[1]
    @test !occursin("keno@juliahub.com", recipients)
    @test occursin("Subject: Re: [PATCH] futex: Prevent robust futex exit race more", hdr)
    @test occursin("In-Reply-To: <87bjc0led9.ffs@fw13>", hdr)
    @test occursin("References: <cover.123.git.keno@juliahub.com>\n    <87bjc0led9.ffs@fw13>", hdr)
    # attribution + quoting, with the mboxrd >From unescaped before quoting
    @test occursin("On Tue, 21 Jul 2026 00:31:48 +0000, Thomas Gleixner <tglx@kernel.org> wrote:", body)
    @test occursin("> Looks good to me.\n>\n> From my side, no objections.", body)

    # "Re:" not doubled, References created when absent
    msg2 = "From: a@b.c\nSubject: Re: hi\nMessage-ID: <x@y>\n\nbody\n"
    reply2, _ = build_reply(msg2)
    @test occursin("Subject: Re: hi\n", reply2)
    @test !occursin("Re: Re:", reply2)
    @test occursin("References: <x@y>\n", reply2)

    # the template survives the draft pipeline with headers intact
    msg3, _ = build_reply(msg; my_email = "keno@juliahub.com")
    final = patch_to_rfc822(msg3)
    @test occursin("In-Reply-To: <87bjc0led9.ffs@fw13>", final)
    @test occursin("=?UTF-8?B?QW5kcsOpIEFsbWVpZGE=?= <andrealmeid@igalia.com>", final)
end

@testset "format_address" begin
    @test format_address("andre@example.com") == "andre@example.com"
    @test format_address("  andre@example.com ") == "andre@example.com"
    @test format_address("<andre@example.com>") == "<andre@example.com>"
    @test format_address("Andre Almeida <andre@example.com>") == "Andre Almeida <andre@example.com>"

    # non-ASCII display name → RFC 2047 encoded-word
    enc = format_address("André Almeida <andre@example.com>")
    @test enc == "=?UTF-8?B?$(base64encode("André Almeida"))?= <andre@example.com>"
    m = match(r"^=\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?= <andre@example\.com>$", enc)
    @test m !== nothing
    @test String(base64decode(m.captures[1])) == "André Almeida"

    # long non-ASCII names chunk into multiple ≤75-char encoded-words
    long = format_address("Ærø Ærø Ærø Ærø Ærø Ærø Ærø Ærø Ærø Ærø Ærø Ærø <ae@example.com>")
    words = split(chopsuffix(long, " <ae@example.com>"), ' ')
    @test length(words) > 1
    @test all(w -> startswith(w, "=?UTF-8?B?") && endswith(w, "?=") && length(w) <= 75, words)
    @test join(String.(base64decode.(chopsuffix.(chopprefix.(words, "=?UTF-8?B?"), "?="))), "") ==
          "Ærø Ærø Ærø Ærø Ærø Ærø Ærø Ærø Ærø Ærø Ærø Ærø"

    # ASCII specials get quoted so the comma isn't an address separator
    @test format_address("Almeida, Andre <andre@example.com>") == "\"Almeida, Andre\" <andre@example.com>"
    @test format_address("Andre \"Tux\" Almeida <a@b.c>") == "\"Andre \\\"Tux\\\" Almeida\" <a@b.c>"
end

@testset "b64url" begin
    # RFC 7636 appendix B PKCE vector
    verifier_bytes = UInt8[116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
                           187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
                           132, 141, 121]
    @test b64url(verifier_bytes) == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
end

@testset "patch_to_rfc822" begin
    patch = """
        From 1234567890abcdef1234567890abcdef12345678 Mon Sep 17 00:00:00 2001
        From: Keno Fischer <keno@juliahub.com>
        Date: Mon, 21 Jul 2026 12:00:00 +0000
        Subject: [PATCH] Fix the frobnicator

        ---
         a.txt | 1 +
         1 file changed, 1 insertion(+)
        """
    msg = patch_to_rfc822(patch; to = ["a@example.com", "b@example.com"], cc = ["c@example.com"])
    @test startswith(msg, "From: Keno Fischer")
    @test occursin("\nTo: a@example.com,\n    b@example.com\n", msg)
    @test occursin("\nCc: c@example.com\n", msg)
    @test !occursin("Mon Sep 17 00:00:00 2001", msg)
    @test occursin("Subject: [PATCH] Fix the frobnicator", msg)
    @test endswith(msg, "\n\n---\n a.txt | 1 +\n 1 file changed, 1 insertion(+)\n")

    # no mbox separator, no recipients → message unchanged
    plain = "From: x@y.z\nSubject: s\n\nbody\n"
    @test patch_to_rfc822(plain) == plain

    # To:/Cc: already present in the patch (git format-patch --to/--cc writes
    # them verbatim, unencoded, possibly folded) get re-encoded and merged
    kernel = """
        From 430ce869f34b548ff57ea9539a1187e739f3b96e Mon Sep 17 00:00:00 2001
        From: Keno Fischer <keno@juliahub.com>
        Date: Tue, 21 Jul 2026 00:31:48 +0000
        Subject: [PATCH] futex: Prevent robust futex exit race more
        To: Thomas Gleixner <tglx@kernel.org>,
            Ingo Molnar <mingo@redhat.com>
        Cc: Darren Hart <dvhart@infradead.org>,
            André Almeida <andrealmeid@igalia.com>,
            stable@vger.kernel.org

        André fixed this before.
        Cc: stable@vger.kernel.org
        ---
         kernel/futex/core.c | 1 +
        """
    msg = patch_to_rfc822(kernel; cc = ["extra@example.com", "stable@vger.kernel.org"])
    hdr, body = split(msg, "\n\n"; limit = 2)
    # no raw non-ASCII survives in the headers; the name is an encoded-word
    @test isascii(hdr)
    @test occursin("=?UTF-8?B?$(base64encode("André Almeida"))?= <andrealmeid@igalia.com>", hdr)
    @test occursin("To: Thomas Gleixner <tglx@kernel.org>,\n    Ingo Molnar <mingo@redhat.com>", hdr)
    # CLI --cc merged into the single Cc: header, duplicates dropped
    @test length(collect(eachmatch(r"^Cc: "m, hdr))) == 1
    @test occursin("extra@example.com", hdr)
    @test length(collect(eachmatch(r"stable@vger\.kernel\.org", hdr))) == 1
    # body (including its trailer lines and non-ASCII text) is untouched
    @test body == "André fixed this before.\nCc: stable@vger.kernel.org\n---\n kernel/futex/core.c | 1 +\n"
end
