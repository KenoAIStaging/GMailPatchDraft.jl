using GMailPatchDraft: b64url, patch_to_rfc822
using Test

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
    @test startswith(msg, "To: a@example.com, b@example.com\nCc: c@example.com\nFrom: Keno Fischer")
    @test !occursin("Mon Sep 17 00:00:00 2001", msg)
    @test occursin("Subject: [PATCH] Fix the frobnicator", msg)

    # no mbox separator, no recipients → message unchanged
    plain = "From: x@y.z\nSubject: s\n\nbody\n"
    @test patch_to_rfc822(plain) == plain
end
