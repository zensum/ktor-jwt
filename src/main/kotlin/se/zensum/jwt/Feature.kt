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

    private fun jwkURL() =
        jwkURL ?: getEnv("JWK_URL")
    private fun issuer(): String =
        issuer ?: getEnv("JWT_ISSUER")
    private fun audience(): String =
        audience ?: getEnv("JWT_AUDIENCE", "")

    fun jwkURL(url: String) {
        this.jwkURL = url
    }

    fun issuer(iss: String) {
        this.issuer = iss
    }

    fun audience(aud: String) {
        this.audience = aud
    }

    private fun jwkProvider() =
        JwkProviderBuilder(jwkURL()).build()

    internal fun getConfig() =
        JWTConfig(jwkProvider(), issuer(), audience())

    fun getVerifier(): JWTVerifier = getConfig().verifier
}

class JWTFeature internal constructor(private val provider: JWTProvider) {
    private fun intercept(context: PipelineContext<Unit, ApplicationCall>) {
        context.call.apply {
            request.authorization()?.let {
                provider.verifyAuthorizationHeader(it)
            }?.let {
                attributes.put(REQUEST_KEY, it)
            }
        }
    }

    companion object Feature: ApplicationFeature<ApplicationCallPipeline, Configuration, JWTFeature> {
        override val key: AttributeKey<JWTFeature> = AttributeKey("JWT")
        override fun install(pipeline: ApplicationCallPipeline, configure: Configuration.() -> Unit): JWTFeature {
            val cfg = Configuration().apply(configure).getConfig()
            val jwtProvider = JWTProviderImpl(cfg)
            val feature = JWTFeature(jwtProvider)
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