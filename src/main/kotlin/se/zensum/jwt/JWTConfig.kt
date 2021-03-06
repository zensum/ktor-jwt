package se.zensum.jwt

import com.auth0.jwk.JwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm

class JWTConfig(provider: JwkProvider,
                private val issuer: String?,
                private val audience: String?) {
    private val algorithm = Algorithm.RSA256(JWKKeyProvider(provider))

    private fun hasIssuer() = !issuer.isNullOrBlank()
    private fun hasAudience() = !audience.isNullOrBlank()

    private fun mkVerifier(): JWTVerifier =
        JWT.require(algorithm)
            .let { if (hasIssuer()) it.withIssuer(issuer!!) else it }
            .let { if (hasAudience()) it.withAudience(audience!!) else it }
            .build()

    val verifier: JWTVerifier by lazy { mkVerifier() }
}