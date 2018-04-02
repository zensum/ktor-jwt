package se.zensum.jwt

import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT

import mu.KLogging

class JWTProviderImpl(private val verifier: JWTVerifier) : JWTProvider {
    companion object: KLogging()

    override fun verifyJWT(token: String): DecodedJWT? =
        try {
            verifier.verify(token)
        } catch (exception: JWTVerificationException) {
            logger.warn({
                "JWT verifcation failed: ${exception.javaClass.name}, ${exception.message}"
            })
            null
        }
}