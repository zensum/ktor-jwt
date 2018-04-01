package se.zensum.jwt

import com.auth0.jwt.interfaces.DecodedJWT
import io.ktor.http.Headers

interface JWTProvider {
    fun verifyAuthorizationHeader(authorizationHeader: String) : DecodedJWT?
    fun verifyJWT(token: String): DecodedJWT?
}