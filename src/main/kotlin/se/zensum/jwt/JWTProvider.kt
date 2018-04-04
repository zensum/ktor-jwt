package se.zensum.jwt

import com.auth0.jwt.interfaces.DecodedJWT

interface JWTProvider {
    fun verifyJWT(token: String): DecodedJWT?
}