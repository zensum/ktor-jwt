package se.zensum.jwt

import com.auth0.jwk.JwkProvider
import com.auth0.jwk.UrlJwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.InvalidClaimException
import com.auth0.jwt.exceptions.JWTDecodeException
import com.auth0.jwt.exceptions.SignatureVerificationException
import com.auth0.jwt.exceptions.TokenExpiredException
import com.auth0.jwt.interfaces.DecodedJWT
import mu.KotlinLogging
import org.jetbrains.ktor.util.ValuesMap
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

private val log = KotlinLogging.logger("auth")

class JWTConfig {
    private val provider: JwkProvider = UrlJwkProvider(getEnv("JWK_URL"))
    private val keyId: String = getEnv("JWT_KEY_ID")
    val keyIssuer: String = getEnv("JWT_KEY_ISSUER")
    val publicKey: RSAPublicKey = provider[keyId].publicKey as RSAPublicKey
    val privateKey: RSAPrivateKey? = null
}


suspend fun verifyToken(config: JWTConfig, headers: ValuesMap, path: String): DecodedJWT? {
    val tokenField: String = headers["Authorization"] ?: return null
    val token: String = tokenField.removePrefix("Bearer ")
    val algorithm = Algorithm.RSA256(config.publicKey, config.privateKey)
    val verifier: JWTVerifier = JWT.require(algorithm)
        .withIssuer(config.keyIssuer)
        .build()

    return verifyToken(verifier, token, path)
}

private suspend fun verifyToken(verifier: JWTVerifier, token: String, path: String): DecodedJWT? {
    return try {
        verifier.verify(token)
    }
    catch(exception: Exception) {
        val signature: String = token.split(".")[2]
        when(exception) {
            is SignatureVerificationException -> log.warn("Verification failed for signature $signature for request to $path.")
            is TokenExpiredException -> log.warn("An expired token with $signature was used for request to $path.")
            is InvalidClaimException -> log.warn("Request to $path with $signature contained an invalid claim.")
            is JWTDecodeException -> log.error("Could not decode token from Base64 to JSON.")
            else -> throw exception
        }
        null
    }
}

fun getEnv(e : String, default: String? = null) : String = System.getenv()[e] ?: default ?: throw RuntimeException("Missing environment variable $e and no default value is given.")