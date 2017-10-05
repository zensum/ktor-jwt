import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import se.zensum.jwt.isValidJwtSyntax

const val validToken: String = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE"
const val validShortToken: String = "aaa.bbb.cc-c_c"
const val invalidWithoutTwoDots: String = "aaabbb.cc-c_c"

class JwtSyntaxTest {
    @Test
    fun testJwtSyntaxFull() {
        assertTrue(isValidJwtSyntax((validToken)))
    }

    @Test
    fun testJwtSyntaxShort() {
        assertTrue(isValidJwtSyntax((validShortToken)))
    }

    @Test
    fun testJwtSyntaxIsNotValid() {
        assertFalse(isValidJwtSyntax(invalidWithoutTwoDots))
    }
}