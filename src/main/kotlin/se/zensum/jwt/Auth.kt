package se.zensum.jwt

import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT

import mu.KLogging

class JWTProviderImpl(private val config: JWTConfig) : JWTProvider {
    companion object: KLogging()

    override fun verifyJWT(token: String): DecodedJWT? =
        try {
            if(!isValidJwtSyntax(token)) {
                logger.debug("Got JWT that does not conform to expected syntax: $token")
                null
            } else config.verifier.verify(token)
        } catch (exception: JWTVerificationException) {
            logger.warn({
                "JWT verifcation failed: ${exception.javaClass.name}, ${exception.message}"
            })
            null
        }
}

private val base64 = Regex("[\\w\\-_=]")
private val jwtRegex = Regex("$base64+\\.$base64+\\.$base64+")
fun isValidJwtSyntax(token: String): Boolean = token.matches(jwtRegex)

fun getEnv(e : String, default: String? = null) : String = System.getenv()[e] ?: default ?: throw RuntimeException("Missing environment variable $e and no default value is given.")