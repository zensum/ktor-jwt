package se.zensum.jwt

import com.auth0.jwk.JwkProviderBuilder
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.interfaces.DecodedJWT
import io.ktor.application.ApplicationCall
import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.ApplicationFeature
import io.ktor.application.call
import io.ktor.pipeline.PipelineContext
import io.ktor.request.authorization
import io.ktor.util.AttributeKey

private val REQUEST_KEY = AttributeKey<DecodedJWT>("jwt")


class Configuration internal constructor() {
    private var jwkURL: String? = null
    private var issuer: String? = null
    private var audience: String? = null
    private var configOverride: JWTConfig? = null
    private var providerOverride: JWTProvider? = null

    private fun jwkURL() =
        jwkURL ?: getEnv("JWK_URL")
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

private const val BEARER_AUTH_TYPE = "Bearer "
class JWTFeature internal constructor(private val provider: JWTProvider) {
    private fun intercept(context: PipelineContext<Unit, ApplicationCall>) {
        context.call.apply {
            request.authorization()?.takeIf {
                it.startsWith(BEARER_AUTH_TYPE)
            }?.removePrefix(BEARER_AUTH_TYPE)?.trim()?.let {
                provider.verifyJWT(it)
            }?.let {
                attributes.put(REQUEST_KEY, it)
            }
        }
    }

    companion object Feature: ApplicationFeature<ApplicationCallPipeline, Configuration, JWTFeature> {
        override val key: AttributeKey<JWTFeature> = AttributeKey("JWT")
        override fun install(pipeline: ApplicationCallPipeline, configure: Configuration.() -> Unit): JWTFeature {
            val provider = Configuration().apply(configure).getProvider()
            val feature = JWTFeature(provider)
            pipeline.intercept(ApplicationCallPipeline.Call) {
                feature.intercept(this)
            }
            return feature
        }
    }
}

fun PipelineContext<Unit, ApplicationCall>.isVerified(): Boolean = this.call.isVerified()
fun PipelineContext<Unit, ApplicationCall>.token(): DecodedJWT? = this.call.token()
fun ApplicationCall.isVerified(): Boolean = token() != null
fun ApplicationCall.token(): DecodedJWT? =
    if (REQUEST_KEY in attributes)
        attributes[REQUEST_KEY]
    else null