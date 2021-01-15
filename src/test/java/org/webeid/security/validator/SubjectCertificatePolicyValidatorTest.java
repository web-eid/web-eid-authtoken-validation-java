package org.webeid.security.validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import org.webeid.security.testutil.AbstractTestWithMockedDateAndCorrectNonce;
import org.webeid.security.testutil.Tokens;
import org.webeid.security.validator.AuthTokenValidator;

import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.webeid.security.testutil.AuthTokenValidators.getAuthTokenValidatorWithDisallowedESTEIDPolicy;

class SubjectCertificatePolicyValidatorTest extends AbstractTestWithMockedDateAndCorrectNonce {

    private AuthTokenValidator validator;

    @BeforeEach
    void setUp() {
        try {
            validator = getAuthTokenValidatorWithDisallowedESTEIDPolicy(cache);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void testX5cDisallowedPolicyCertificate() {
        // Tokens.SIGNED has EST IDEMIA policy which is configured as disallowed in setUp().
        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(UserCertificateDisallowedPolicyException.class);
    }
}
