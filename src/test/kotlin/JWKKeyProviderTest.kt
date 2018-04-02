package se.zensum.jwt

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import org.junit.Test
import java.math.BigInteger
import org.apache.commons.codec.binary.Base64
import kotlin.test.*

private val RS_256 = "RS256"
private val RSA = "RSA"
private val THUMBPRINT = "THUMBPRINT"
private val SIG = "sig"
private val MODULUS = "vGChUGMTWZNfRsXxd-BtzC4RDYOMqtIhWHol--HNib5SgudWBg6rEcxvR6LWrx57N6vfo68wwT9_FHlZpaK6NXA_dWFW4f3NftfWLL7Bqy90sO4vijM6LMSE6rnl5VB9_Gsynk7_jyTgYWdTwKur0YRec93eha9oCEXmy7Ob1I2dJ8OQmv2GlvA7XZalMxAq4rFnXLzNQ7hCsHrUJP1p7_7SolWm9vTokkmckzSI_mAH2R27Z56DmI7jUkL9fLU-jz-fz4bkNg-mPz4R-kUmM_ld3-xvto79BtxJvOw5qqtLNnRjiDzoqRv-WrBdw5Vj8Pvrg1fwscfVWHlmq-1pFQ"
private val EXPONENT = "AQAB"
private val CERT_CHAIN = "CERT_CHAIN"

private fun generateJWK(kid: String) = Jwk(
    kid,
    RSA,
    RS_256,
    SIG,
    listOf("sign"),
    null,
    listOf(CERT_CHAIN),
    THUMBPRINT,
    mapOf("n" to MODULUS, "e" to EXPONENT)
)

class JWKKeyProviderTest {
    private val dummyJWKProvider = JwkProvider {
        generateJWK(it)
    }
    private val kprovider = JWKKeyProvider(dummyJWKProvider)
    @Test fun testUnsupportedGetPrivateKey() {
        assertFailsWith<UnsupportedOperationException> {
            kprovider.privateKey
        }
    }

    @Test fun testUnsupportedGetPrivateKeyId() {
        assertFailsWith<UnsupportedOperationException> {
            kprovider.privateKeyId
        }
    }

    @Test fun getKey() {
        val pk = kprovider.getPublicKeyById("foo")
        assertNotNull(pk)
        val exponent = BigInteger(1, Base64.decodeBase64(EXPONENT))
        val modulus = BigInteger(1, Base64.decodeBase64(MODULUS))
        assertEquals(exponent, pk.publicExponent)
        assertEquals(modulus, pk.modulus)
    }
}