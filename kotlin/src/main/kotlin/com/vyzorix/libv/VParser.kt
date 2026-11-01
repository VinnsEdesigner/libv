package com.vyzorix.libv

/**
 * One parsed line: its depth, its decoded tokens, and its children.
 *
 * [depth] is the count of leading `v` characters. [tokens] are the decoded values
 * (quotes removed), so `v name "Bench 3"` yields `["name", "Bench 3"]`.
 */
data class VNode(
    val depth: Int,
    val tokens: List<String>,
    val children: MutableList<VNode> = mutableListOf(),
) {
    /** The first token, which is the node's type/name by convention. */
    val key: String get() = tokens.firstOrNull() ?: ""

    /**
     * Every descendant whose first token equals the next dot-separated segment.
     * `Find("apps.app")` walks `apps` then `app`, one level per segment.
     */
    fun find(path: String): List<VNode> {
        var current = listOf(this)
        for (segment in path.split('.')) {
            current = current.flatMap { parent -> parent.children.filter { it.key == segment } }
            if (current.isEmpty()) return emptyList()
        }

        return current
    }
}

/** A malformed document, with the 1-based line number. */
class VParseError(
    val line: Int,
    message: String,
) : Exception("libv: line $line: $message")

/** The parsed signature line. */
data class VSignature(
    val algorithm: String,
    val value: String,
    val depth: Int,
    val line: Int,
) {
    companion object {
        const val ALG_ECDSA_P256 = "ecdsa-p256"
        const val ALG_HMAC_SHA256 = "hmac-sha256"
    }
}

/** A parsed document: the tree, and the signature line if one was present. */
data class VDocument(
    val root: VNode,
    val signature: VSignature?,
) {
    val signed: Boolean get() = signature != null
}

/**
 * Parser for the vyzorix.v format. See `spec/SPEC.md` for the frozen grammar;
 * this is an implementation of it, and `vectors/` is the conformance contract
 * that this and the Go implementation must both satisfy.
 */
object VParser {

    /**
     * Reads a document.
     *
     * Strict about the two structural errors that would otherwise silently produce
     * a wrong tree — a depth jump, and a node line with no `v` — and lenient about
     * everything else, per SPEC §1.
     */
    fun parse(text: String): VDocument {
        val root = VNode(0, listOf("root"))
        val stack = ArrayDeque<VNode>().apply { addLast(root) }
        var prevDepth = 0
        var signature: VSignature? = null

        text.split('\n').forEachIndexed { index, raw ->
            val lineNo = index + 1
            val trimmed = raw.trim()

            // SPEC §1: blank lines, comments, and anything that is not a node are
            // skipped. Depth is counted on the *trimmed* line, so an indented
            // document parses identically to the same document flush-left.
            if (trimmed.isEmpty() || trimmed.startsWith("'")) return@forEachIndexed
            if (!trimmed.startsWith("v")) return@forEachIndexed

            val depth = trimmed.takeWhile { it == 'v' }.length

            // A 'v' run must be followed by a separator or end of line: "value" is
            // a word beginning with 'v', not a depth-1 node.
            if (depth < trimmed.length && trimmed[depth] != ' ' && trimmed[depth] != '\t') {
                return@forEachIndexed
            }

            if (depth == 0) throw VParseError(lineNo, "depth must be at least 1")
            if (depth > prevDepth + 1) {
                throw VParseError(lineNo, "depth jump: $prevDepth -> $depth")
            }

            val content = trimmed.substring(depth).trim()
            if (content.isEmpty()) throw VParseError(lineNo, "node has no tokens")

            val tokens = tokenize(content, lineNo)

            // The signature is recognised by its first two tokens, not by a
            // substring, so a value merely containing "sig" is unaffected.
            if (tokens.size >= 3 && tokens[0] == "sig") {
                if (signature != null) throw VParseError(lineNo, "duplicate signature line")
                if (depth != 1) throw VParseError(lineNo, "signature must be at depth 1")
                signature = VSignature(tokens[1], tokens[2], depth, lineNo)
                prevDepth = depth
                return@forEachIndexed
            }

            if (signature != null) {
                // A node after the signature would be excluded from the canonical
                // string, so it would be unauthenticated while appearing signed.
                throw VParseError(lineNo, "signature line must be the last node")
            }

            while (stack.size > depth) stack.removeLast()

            val node = VNode(depth, tokens)
            stack.last().children.add(node)
            stack.addLast(node)
            prevDepth = depth
        }

        return VDocument(root, signature)
    }

    /**
     * Splits a node's content into decoded tokens. A quoted token may contain
     * spaces; the quotes are not part of the value.
     */
    internal fun tokenize(
        content: String,
        lineNo: Int,
    ): List<String> {
        val out = mutableListOf<String>()
        var i = 0
        while (i < content.length) {
            when {
                content[i] == ' ' || content[i] == '\t' -> i++
                content[i] == '"' -> {
                    val end = content.indexOf('"', i + 1)
                    if (end == -1) throw VParseError(lineNo, "unclosed quote")
                    out.add(content.substring(i + 1, end))
                    i = end + 1
                }
                else -> {
                    var end = i
                    while (end < content.length &&
                        content[end] != ' ' &&
                        content[end] != '\t' &&
                        content[end] != '"'
                    ) {
                        end++
                    }
                    out.add(content.substring(i, end))
                    i = end
                }
            }
        }

        return out
    }

    /**
     * The bytes a signature covers: every node line above the signature, in order,
     * with depth written explicitly and tokens joined by one space.
     *
     * This is the single canonicaliser, used by both signing and verification. Two
     * implementations of this string would be two things that can disagree, and
     * the signature depends on them agreeing forever.
     */
    fun canonicalString(text: String): ByteArray {
        val out = StringBuilder()

        text.split('\n').forEach { raw ->
            val trimmed = raw.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("'")) return@forEach
            if (!trimmed.startsWith("v")) return@forEach

            val depth = trimmed.takeWhile { it == 'v' }.length
            if (depth < trimmed.length && trimmed[depth] != ' ' && trimmed[depth] != '\t') {
                return@forEach
            }
            if (depth == 0) return@forEach

            val content = trimmed.substring(depth).trim()
            if (content.isEmpty()) return@forEach

            // tokenize here cannot fail on a document that parsed, but a caller may
            // canonicalise text it has not parsed, so the quote error is surfaced.
            val tokens = tokenize(content, 0)

            // The signature line is excluded from what it signs.
            if (tokens.size >= 3 && tokens[0] == "sig") return@forEach

            out.append("v".repeat(depth))
            out.append(' ')
            out.append(tokens.joinToString(" "))
            out.append('\n')
        }

        return out.toString().toByteArray(Charsets.UTF_8)
    }
}
