package se.zensum.jwt

import com.auth0.jwk.JwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import io.ktor.http.Headers

import mu.KotlinLogging

private val log = KotlinLogging.logger("auth")

class JWTConfig(private val provider: JwkProvider,
                private val issuer: String?,
                private val audience: String?) {
    private val algorithm = Algorithm.RSA256(JWKKeyProvider(provider))

    private fun hasIssuer() = (issuer != null) && issuer.isNotBlank()
    private fun hasAudience() = (issuer != null) && issuer.isNotBlank()

    private fun mkVerifier(): JWTVerifier =
        JWT.require(algorithm)
            .let { if (hasIssuer()) it.withIssuer(issuer!!) else it }
            .let { if (hasAudience()) it.withAudience(audience!!) else it }
            .build()

    val verifier: JWTVerifier by lazy { mkVerifier() }
}

suspend fun verifyToken(config: JWTConfig, headers: Headers, path: String): DecodedJWT? {
    val tokenField: String = headers["Authorization"] ?: return null
    val token: String = tokenField.removePrefix("Bearer ")

    if(tokenField.length == token.length) {
        log.debug("Got Authorization field without Bearer prefix: $tokenField")
        return null
    }

    if(!isValidJwtSyntax(token)) {
        log.debug("Got JWT that does not conform to expected syntax: $token")
        return null
    }
    return verifyToken(config.verifier, token)
}

private fun verifyToken(verifier: JWTVerifier, token: String): DecodedJWT? =
    try {
        verifier.verify(token)
    } catch (exception: JWTVerificationException) {
        log.warn({
            "JWT verifcation failed: ${exception.javaClass.name}, ${exception.message}"
        })
        null
    }

private val base64 = Regex("[\\w\\-_=]")
private val jwtRegex = Regex("$base64+\\.$base64+\\.$base64+")

fun isValidJwtSyntax(token: String): Boolean = token.matches(jwtRegex)

fun getEnv(e : String, default: String? = null) : String = System.getenv()[e] ?: default ?: throw RuntimeException("Missing environment variable $e and no default value is given.")