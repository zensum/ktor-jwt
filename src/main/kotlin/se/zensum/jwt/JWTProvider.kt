package se.zensum.jwt

import com.auth0.jwt.interfaces.DecodedJWT
import io.ktor.http.Headers

interface JWTProvider {
    fun verifyJWT(token: String): DecodedJWT?
}