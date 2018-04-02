package se.zensum.jwt

import com.auth0.jwk.JwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.interfaces.DecodedJWT
import io.ktor.application.*
import io.ktor.http.*
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.server.testing.*
import org.junit.Test
import kotlin.test.*

private fun configure(fn: Configuration.() -> Unit) = Configuration().apply(fn)

private fun ensureNoEnv(env: String) {
    if (!System.getenv(env).isNullOrEmpty()) {
        throw Exception("$env is set in the testing environment, this breaks the test")
    }
}

class TestConfiguration {
    private val mockProvider = object : JWTProvider {
        override fun verifyJWT(token: String): DecodedJWT? = null
    }
    private val dummyConfig = JWTConfig(JwkProvider { null }, null, null)
    @Test fun testConfigurationOverridesProvider() {
        val gottenProvider = configure {
            jwtProvider(mockProvider)
        }.getProvider()
        assertEquals(mockProvider, gottenProvider)
    }
    @Test fun missingUrlThrows() {
        ensureNoEnv("JWK_URL")
        assertFailsWith<RuntimeException> {
            configure {
                issuer("someone")
                audience("someonee else")
            }.getProvider()
        }
    }
    @Test fun missingIssuerThrows() {
        ensureNoEnv("JWT_ISSUER")
        assertFailsWith<RuntimeException> {
            configure {
                jwkURL("opensource-tests.eu.auth0.com")
                audience("whee")
            }.getProvider()
        }
    }
    @Test fun missingAudienceAllowed() {
        ensureNoEnv("JWT_AUDIENCE")
        configure {
            jwkURL("opensource-tests.eu.auth0.com")
            issuer("rhee")
        }
    }

    @Test fun settingVariableAndConfigCrashes() {

        assertFailsWith<UnsupportedOperationException> {
            configure {
                jwkURL("foobar")
                jwtConfig(dummyConfig)
            }
        }
        assertFailsWith<UnsupportedOperationException> {
            configure {
                audience("foo")
                jwtConfig(dummyConfig)
            }
        }
        assertFailsWith<UnsupportedOperationException> {
            configure {
                issuer("foo")
                jwtConfig(dummyConfig)
            }
        }
    }
    @Test fun settingVariableAndProviderCrashes() {
        assertFailsWith<UnsupportedOperationException> {
            configure {
                jwtConfig(dummyConfig)
                jwtProvider(mockProvider)
            }
        }
        assertFailsWith<UnsupportedOperationException> {
            configure {
                jwkURL("whee")
                jwtProvider(mockProvider)
            }
        }
    }

}