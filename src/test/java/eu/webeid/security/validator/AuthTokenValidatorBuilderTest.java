// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator;

import eu.webeid.security.testutil.AuthTokenValidators;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AuthTokenValidatorBuilderTest {

    // AuthTokenValidationConfiguration has a package-private constructor, but some tests need access to it outside its package.
    // Provide a public accessor to it for these tests.
    public static final AuthTokenValidationConfiguration CONFIGURATION = new AuthTokenValidationConfiguration();

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

    @Test
    void testInvalidOcspResponseTimeSkew() throws Exception {
        final AuthTokenValidatorBuilder builderWithInvalidOcspResponseTimeSkew = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withAllowedOcspResponseTimeSkew(Duration.ofMinutes(-1));
        assertThatThrownBy(builderWithInvalidOcspResponseTimeSkew::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("Allowed OCSP response time-skew must be greater than zero");
    }

    @Test
    void testInvalidMaxOcspResponseThisUpdateAge() throws Exception {
        final AuthTokenValidatorBuilder builderWithInvalidOcspResponseTimeSkew = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withMaxOcspResponseThisUpdateAge(Duration.ZERO);
        assertThatThrownBy(builderWithInvalidOcspResponseTimeSkew::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("Max OCSP response thisUpdate age must be greater than zero");
    }

    @Test
    void testInvalidOcspRequestTimeout() throws Exception {
        final AuthTokenValidatorBuilder builderWithInvalidOcspResponseTimeSkew = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withOcspRequestTimeout(Duration.ofMinutes(-1));
        assertThatThrownBy(builderWithInvalidOcspResponseTimeSkew::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("OCSP request timeout must be greater than zero");
    }
}
