package org.webeid.security.validator;

import org.junit.jupiter.api.Test;
import org.webeid.security.testutil.AbstractTestWithCache;

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
            .withSiteOrigin(URI.create("https://ria.ee"))
            .withNonceCache(AbstractTestWithCache.createCache("AuthTokenValidatorBuilderTest"));
        assertThatThrownBy(builderWithMissingRootCa::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("At least one trusted root certificate authority must be provided");
    }

}
