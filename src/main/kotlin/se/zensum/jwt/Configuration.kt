package se.zensum.jwt

import com.auth0.jwk.JwkProviderBuilder

private fun getEnv(e : String, default: String? = null) : String = System.getenv()[e] ?: default ?: throw RuntimeException("Missing environment variable $e and no default value is given.")

private const val JWKS_SUFFIX = ".well-known/jwks.json"

class Configuration internal constructor() {
    private var jwkURL: String? = null
    private var issuer: String? = null
    private var audience: String? = null
    private var configOverride: JWTConfig? = null
    private var providerOverride: JWTProvider? = null

    private fun jwkURL() =
        (jwkURL ?: getEnv("JWK_URL")).removeSuffix(JWKS_SUFFIX)
    private fun issuer(): String =
        issuer ?: getEnv("JWT_ISSUER")
    private fun audience(): String =
        audience ?: getEnv("JWT_AUDIENCE", "")

    private fun throwIfConfigSet() {
        if (configOverride != null || providerOverride != null) {
            throw UnsupportedOperationException("cannot set config after setting override")
        }
    }
    fun jwkURL(url: String) {
        throwIfConfigSet()
        this.jwkURL = url
    }

    fun issuer(iss: String) {
        throwIfConfigSet()
        this.issuer = iss
    }

    fun audience(aud: String) {
        throwIfConfigSet()
        this.audience = aud
    }

    fun jwtConfig(jwtConfig: JWTConfig) {
        if (jwkURL != null || issuer != null || audience != null) {
            throw UnsupportedOperationException("Cannot set jwtConfig after setting anything else!")
        }
        this.configOverride = jwtConfig
    }

    fun jwtProvider(jwtProvider: JWTProvider) {
        if (jwkURL != null || issuer != null || audience != null || configOverride != null) {
            throw UnsupportedOperationException("Cannot set jwtProvider after setting anything else!")
        }
        this.providerOverride = jwtProvider
    }

    private fun jwkProvider() =
        JwkProviderBuilder(jwkURL()).build()

    private fun getConfig() =
        configOverride ?: JWTConfig(jwkProvider(), issuer(), audience())
    internal fun getProvider(): JWTProvider =
        providerOverride ?: JWTProviderImpl(getConfig().verifier)
}