package com.vyzorix.libv

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The Kotlin implementation's tests, including the shared vectors.
 *
 * The vectors are the cross-language contract: this test and the Go test read the
 * same files, so if the two implementations ever disagree about the canonical
 * string, one of them fails here.
 */
class VParserTest {

    private val vectorsDir = File("../../vectors")

    private val full =
        """
        v device nokia-c22-03
        vv org vyzorix-workshop-kisumu
        vv name Bench 3
        vv cloud
        vvv ws wss://api.vyzorix.com/ws/device
        vvv hb 30s
        vvv backoff 1s>30s
        vv apps root /data/local/vyzorix-apps > /home/apps autostart true
        vvv app flasher-server 3000
        vvvv cmd npm start -- --port 3000
        """.trimIndent()

    @Test
    fun `parses a minimal document`() {
        val doc = VParser.parse("v device nokia-c22-03\n")

        assertFalse(doc.signed)
        assertEquals(1, doc.root.children.size)
        assertEquals(listOf("device", "nokia-c22-03"), doc.root.children[0].tokens)
    }

    @Test
    fun `builds the tree from depth`() {
        val doc = VParser.parse(full)
        val device = doc.root.children[0]

        assertEquals("device", device.key)

        // `vv name Bench 3` is one node with three tokens: the value is unquoted
        // and multi-word, exactly as in the format's own example.
        val names = device.find("name")
        assertEquals(1, names.size)
        assertEquals(3, names[0].tokens.size)

        // `vv apps` is depth 2, `vvv app` is depth 3, so the app hangs off apps.
        val app = device.find("apps.app")
        assertEquals(1, app.size)
        assertEquals("flasher-server", app[0].tokens[1])
        assertEquals("cmd", app[0].children[0].key)
    }

    /** SPEC §7 deviation 1: indentation must not change the parse. */
    @Test
    fun `an indented document parses identically`() {
        val indented = full.lines().joinToString("\n") { "    $it" }

        val flush = VParser.parse(full)
        val spaced = VParser.parse(indented)

        assertEquals(flush.root.children.size, spaced.root.children.size)
        assertEquals(
            flush.root.children[0].children.size,
            spaced.root.children[0].children.size,
        )
    }

    @Test
    fun `a depth jump is an error`() {
        try {
            VParser.parse("v a\nvvv c\n")
            fail("a depth jump must be refused")
        } catch (e: VParseError) {
            assertTrue(e.message!!.contains("depth jump"))
        }
    }

    @Test
    fun `an unclosed quote is an error`() {
        try {
            VParser.parse("v name \"Bench 3\n")
            fail("an unclosed quote must be refused")
        } catch (e: VParseError) {
            assertTrue(e.message!!.contains("unclosed quote"))
        }
    }

    @Test
    fun `a quoted token is one token`() {
        val doc = VParser.parse("v name \"Bench 3\"\n")

        assertEquals(listOf("name", "Bench 3"), doc.root.children[0].tokens)
    }

    @Test
    fun `a signature must be last`() {
        try {
            VParser.parse("v sig ecdsa-p256 AAAA\nv device x\n")
            fail("a node after the signature must be refused")
        } catch (e: VParseError) {
            assertTrue(e.message!!.contains("last"))
        }
    }

    @Test
    fun `a signature must be at depth one`() {
        // `vv sig` is depth 2 with no depth-1 parent, so the depth-jump check
        // fires first — that is the correct refusal, and the test asserts the
        // behaviour rather than a particular message.
        try {
            VParser.parse("vv sig ecdsa-p256 AAAA\n")
            fail("a signature below depth 1 must be refused")
        } catch (e: VParseError) {
            assertTrue(
                e.message!!.contains("depth"),
                "expected a depth complaint, got: ${e.message}",
            )
        }

        // With a parent present, the signature's own depth is what is refused.
        try {
            VParser.parse("v device x\nvv sig ecdsa-p256 AAAA\n")
            fail("a signature at depth 2 must be refused")
        } catch (e: VParseError) {
            assertTrue(
                e.message!!.contains("depth 1"),
                "expected the depth-1 rule, got: ${e.message}",
            )
        }
    }

    /** The canonical string ignores whitespace, comments and the signature. */
    @Test
    fun `canonical form excludes comments and the signature`() {
        val a = VParser.canonicalString("v device x\n")
        val b = VParser.canonicalString("' comment\n\n  v device x\nv sig ecdsa-p256 AAAA\n")

        assertEquals(String(a), String(b))
    }

    @Test
    fun `verification refuses an unsigned document`() {
        val doc = VParser.parse(full)

        try {
            VVerifier.verify(doc, full)
            fail("an unsigned document must not verify")
        } catch (e: VVerifyError.NoSignature) {
            // expected
        }
    }

    @Test
    fun `verification refuses an algorithm it cannot check`() {
        val doc = VParser.parse("v device x\nv sig ecdsa-p256 AAAA\n")

        try {
            VVerifier.verify(doc, "v device x\nv sig ecdsa-p256 AAAA\n", ecdsaKey = null)
            fail("a missing key must not read as a pass")
        } catch (e: VVerifyError.UnsupportedAlgorithm) {
            // expected
        }
    }

    /**
     * The shared vectors. If the Kotlin canonicaliser disagrees with the Go one by
     * a single byte, the signatures will not verify here.
     */
    @Test
    fun `passes every shared vector`() {
        if (!vectorsDir.isDirectory) {
            // The vectors live at the repo root; a build that does not lay them out
            // next to the module skips rather than failing misleadingly.
            return
        }

        val pubKey =
            VVerifier.parsePublicKey(File(vectorsDir, "keys/vector_pub.pem").readText())

        val vectorFiles: Array<File> =
            vectorsDir.listFiles { f: File -> f.name.endsWith(".v") } ?: emptyArray()

        vectorFiles.sortedBy { it.name }.forEach { file ->
                val text = file.readText()
                val name = file.name

                if (name.contains("depth_jump")) {
                    try {
                        VParser.parse(text)
                        fail("$name: expected a parse error")
                    } catch (e: VParseError) {
                        // expected
                    }
                    return@forEach
                }

                val doc = VParser.parse(text)
                if (!doc.signed) return@forEach

                val hmacKey =
                    if (doc.signature!!.algorithm == VSignature.ALG_HMAC_SHA256) {
                        File(vectorsDir, name.removeSuffix(".v") + ".secret").readBytes()
                    } else {
                        null
                    }

                val expectBad = name.contains("tampered")
                try {
                    VVerifier.verify(doc, text, pubKey, hmacKey)
                    if (expectBad) fail("$name: expected a bad signature")
                } catch (e: VVerifyError.BadSignature) {
                    if (!expectBad) fail("$name: signature should have verified: ${e.message}")
                }
            }
    }

    /** The canonical form of vector 02 must match the committed bytes exactly. */
    @Test
    fun `canonical form matches the committed bytes`() {
        val canonicalFile = File(vectorsDir, "02_full.canonical")
        if (!canonicalFile.isFile) return

        val doc = VParser.parse(File(vectorsDir, "02_full.v").readText())
        val mine = String(VParser.canonicalString(File(vectorsDir, "02_full.v").readText()))

        assertEquals(canonicalFile.readText(), mine)
        assertTrue(doc.signed)
    }
}
