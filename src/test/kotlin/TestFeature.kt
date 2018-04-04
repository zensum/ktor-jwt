package se.zensum.jwt

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

class MockJWTProvider(
    private val token: (String) -> DecodedJWT? = { null }
) : JWTProvider {
    override fun verifyJWT(token: String): DecodedJWT? =
        token(token)
}

private fun withApp(jwtProvider: JWTProvider, test: TestApplicationEngine.() -> Unit) {
    return withTestApplication({
        install(JWTFeature) {
            jwtProvider(jwtProvider)
        }
        routing {
            get("/is-auth") {
                if (isVerified()) {
                    call.respondText("yup")
                } else {
                    call.respondText("nope!", status = HttpStatusCode.Unauthorized)
                }
            }
            get("/url-that-doesnt-care") {
                call.respondText("it doesn't really care!")
            }
            get("/echo") {
                val t = call.token()
                call.respondText(if (t != null)
                    t.getClaim("name").asString()
                else "nope!")
            }
        }
    }, test)
}

fun TestApplicationCall.assertStatus(statusCode: HttpStatusCode) =
    assertEquals(statusCode, response.status())

fun TestApplicationCall.assertOK() =
    assertStatus(HttpStatusCode.OK)
fun TestApplicationCall.assertUnauthorized() =
    assertStatus(HttpStatusCode.Unauthorized)
fun TestApplicationCall.assertUnhandled() =
    assertEquals(null, response.status())

class RequestTest {

    private val DUMMY_JWT =
        JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
    val SENTINEL = "SENTINEL"
    private val sentinelMockJWT = MockJWTProvider {
        if (SENTINEL == it)
            DUMMY_JWT
        else
            null
    }
    private val neverAuthMock = MockJWTProvider { null }

    @Test fun testNotAuthorizedWOHeader() {
        withApp(neverAuthMock) {
            with(handleRequest(HttpMethod.Get, "/is-auth", {
                addHeader("SomeOtherHeader", "Rhee")
            })) {
                assertUnauthorized()
            }
        }
    }
    @Test fun testIsAuthorized() {
        withApp(sentinelMockJWT) {
            with(handleRequest(HttpMethod.Get, "/is-auth", {
                addHeader("Authorization", "Bearer SENTINEL")
            })) {
                assertOK()
            }
        }
    }

    @Test fun testDoesntCareAuthorized() {
        withApp(sentinelMockJWT) {
            with(handleRequest(HttpMethod.Get, "/url-that-doesnt-care", {
                addHeader("Authorization", "Bearer SENTINEL")
            })) {
                assertOK()
            }
        }
    }

    @Test fun testDoesntCareNoAuth() {
        withApp(neverAuthMock) {
            with(handleRequest(HttpMethod.Get, "/url-that-doesnt-care")) {
                assertOK()
            }
        }
    }

    // Check that 404 isn't in advertently captured for some reason
    @Test fun test404NoAuth() {
        withApp(neverAuthMock) {
            with(handleRequest(HttpMethod.Get, "/this-url-should-404")) {
                assertUnhandled()
            }
        }
    }
    // Check that 404 isn't in advertently captured for some reason
    @Test fun test404Auth() {
        withApp(sentinelMockJWT) {
            with(handleRequest(HttpMethod.Get, "/this-url-should-404", {
                addHeader("Authorization", "Bearer SENTINEL")
            })) {
                assertUnhandled()
            }
        }
    }

    @Test fun testTokenField() {
        withApp(sentinelMockJWT) {
            with(handleRequest(HttpMethod.Get, "/echo", {
                addHeader("Authorization", "Bearer SENTINEL")
            })) {
                assertOK()
                assertEquals("John Doe", response.content)
            }
        }
    }
}