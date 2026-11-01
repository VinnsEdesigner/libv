package com.vyzorix.libv

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Why verification failed. Distinct types so a caller can tell a tampered
 * document from an unsigned one, which are different situations. */
sealed class VVerifyError(message: String) : Exception(message) {
    /** The document carries no signature line. */
    object NoSignature : VVerifyError("document is not signed")

    /** The signature does not match the canonical string. */
    object BadSignature : VVerifyError("signature does not match")

    /** The signature names an algorithm this build cannot check. */
    class UnsupportedAlgorithm(algorithm: String) :
        VVerifyError("unsupported signature algorithm: $algorithm")

    /** The key could not be parsed, or is not on P-256. */
    class BadKey(detail: String) : VVerifyError("malformed key: $detail")
}

/**
 * Verifies a signed document.
 *
 * ECDSA over P-256 is the default because it needs no shared secret, so nothing
 * has to be transmitted to a device. The legacy HMAC path is retained so an older
 * document still verifies; a verifier that cannot check the named algorithm must
 * fail rather than fall through to "ok".
 */
object VVerifier {

    /** PEM-encoded P-256 public key, as pinned in the app. */
    fun parsePublicKey(pem: String): java.security.PublicKey {
        val body = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(Regex("\\s"), "")

        val der =
            try {
                Base64.getDecoder().decode(body)
            } catch (t: IllegalArgumentException) {
                throw VVerifyError.BadKey("not base64")
            }

        val key =
            try {
                KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der))
            } catch (t: Exception) {
                throw VVerifyError.BadKey(t.message ?: "unparseable")
            }

        // A key on another curve would verify against a canonical string the
        // signer never produced.
        val params = (key as? java.security.interfaces.ECPublicKey)?.params
            ?: throw VVerifyError.BadKey("not an EC key")
        if (params.curve.field.fieldSize != 256) {
            throw VVerifyError.BadKey("expected P-256")
        }

        return key
    }

    /**
     * Verifies [document] against [text].
     *
     * [ecdsaKey] is required for an `ecdsa-p256` document and [hmacKey] for a
     * legacy `hmac-sha256` one. Passing the wrong kind for the document's
     * algorithm is [VVerifyError.UnsupportedAlgorithm], never a silent pass.
     */
    fun verify(
        document: VDocument,
        text: String,
        ecdsaKey: java.security.PublicKey? = null,
        hmacKey: ByteArray? = null,
    ) {
        val sig = document.signature ?: throw VVerifyError.NoSignature
        val canonical = VParser.canonicalString(text)

        when (sig.algorithm) {
            VSignature.ALG_ECDSA_P256 -> {
                val key = ecdsaKey ?: throw VVerifyError.UnsupportedAlgorithm(sig.algorithm)
                val raw =
                    try {
                        Base64.getDecoder().decode(sig.value)
                    } catch (t: IllegalArgumentException) {
                        throw VVerifyError.BadSignature
                    }

                // SHA256withECDSA is what Android's Keystore produces, and it emits
                // ASN.1 DER — the same shape Go's ecdsa.SignASN1 emits.
                val verifier = Signature.getInstance("SHA256withECDSA")
                verifier.initVerify(key)
                verifier.update(canonical)
                if (!verifier.verify(raw)) throw VVerifyError.BadSignature
            }

            VSignature.ALG_HMAC_SHA256 -> {
                val key = hmacKey ?: throw VVerifyError.UnsupportedAlgorithm(sig.algorithm)
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(key, "HmacSHA256"))
                val expected = mac.doFinal(canonical).joinToString("") { "%02x".format(it) }

                // Constant-time: a length-independent compare, since this is a MAC.
                if (!constantTimeEquals(expected, sig.value)) throw VVerifyError.BadSignature
            }

            else -> throw VVerifyError.UnsupportedAlgorithm(sig.algorithm)
        }
    }

    private fun constantTimeEquals(
        a: String,
        b: String,
    ): Boolean {
        val x = a.toByteArray(Charsets.UTF_8)
        val y = b.toByteArray(Charsets.UTF_8)
        if (x.size != y.size) return false

        var diff = 0
        for (i in x.indices) diff = diff or (x[i].toInt() xor y[i].toInt())

        return diff == 0
    }
}
