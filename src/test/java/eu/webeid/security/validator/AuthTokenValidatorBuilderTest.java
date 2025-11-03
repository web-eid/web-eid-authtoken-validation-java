/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package eu.webeid.security.validator;

import eu.webeid.security.testutil.AuthTokenValidators;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthTokenValidatorBuilderTest {

    final AuthTokenValidatorBuilder builder = new AuthTokenValidatorBuilder();

    @Test
    void testOriginMissing() {
        assertThatThrownBy(builder::build)
            .isInstanceOf(NullPointerException.class)
            .hasMessageStartingWith("Origin URI must not be null");
    }

    @Test
    void testRootCertificateAuthorityMissing() {
        final AuthTokenValidatorBuilder builderWithMissingRootCa = builder
            .withSiteOrigin(URI.create("https://ria.ee"));
        assertThatThrownBy(builderWithMissingRootCa::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("At least one trusted certificate authority must be provided");
    }

    @Test
    void testValidatorOriginNotUrl() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("not-url"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testValidatorOriginExcessiveElements() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("https://ria.ee/excessive-element"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testValidatorOriginNotHttps() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("http://ria.ee"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testValidatorOriginNotValidUrl() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("ria://ria.ee"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("Provided URI is not a valid URL");
    }

    @Test
    void testValidatorOriginNotValidSyntax() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("https:///ria.ee"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("An URI syntax exception occurred");
    }

}
