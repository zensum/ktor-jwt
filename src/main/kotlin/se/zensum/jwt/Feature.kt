package se.zensum.jwt

import com.auth0.jwt.interfaces.DecodedJWT
import io.ktor.application.ApplicationCall
import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.ApplicationFeature
import io.ktor.application.call
import io.ktor.pipeline.PipelineContext
import io.ktor.request.authorization
import io.ktor.util.AttributeKey

private val REQUEST_KEY = AttributeKey<DecodedJWT>("jwt")

private const val BEARER_AUTH_TYPE = "Bearer "

private fun extractBearer(x: String?): String? = x
    ?.takeIf { it.startsWith(BEARER_AUTH_TYPE) }
    ?.removePrefix(BEARER_AUTH_TYPE)
    ?.trim()

class JWTFeature internal constructor(private val provider: JWTProvider) {
    private fun intercept(context: PipelineContext<Unit, ApplicationCall>) {
        context.call.apply {
            extractBearer(request.authorization())?.let {
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
fun ApplicationCall.token(): DecodedJWT? = attributes.getOrNull(REQUEST_KEY)