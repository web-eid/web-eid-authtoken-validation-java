/*
 * Copyright (c) 2020 The Web eID Project
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

package org.webeid.security.validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.webeid.security.exceptions.JceException;
import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.exceptions.CertificateExpiredException;
import org.webeid.security.exceptions.UserCertificateRevokedException;
import org.webeid.security.testutil.AbstractTestWithMockedDateAndCorrectNonce;
import org.webeid.security.testutil.Tokens;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.webeid.security.testutil.AuthTokenValidators.getAuthTokenValidatorWithDesignatedOcspCheck;
import static org.webeid.security.testutil.AuthTokenValidators.getAuthTokenValidatorWithOcspCheck;

class OcspTest extends AbstractTestWithMockedDateAndCorrectNonce {

    private AuthTokenValidator validator;

    @Override
    @BeforeEach
    protected void setup() {
        super.setup();
        try {
            validator = getAuthTokenValidatorWithOcspCheck(cache);
        } catch (CertificateException | JceException | URISyntaxException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void detectRevokedUserCertificate() {
        try {
            validator.validate(Tokens.SIGNED);
        } catch (TokenValidationException e) {
            assertThat(e).isInstanceOf(UserCertificateRevokedException.class);
        }
    }

    @Test
    void detectRevokedUserCertificateWithDesignatedOcspService() throws Exception {
        final AuthTokenValidator validatorWithDesignatedOcspCheck = getAuthTokenValidatorWithDesignatedOcspCheck(cache);
        try {
            validatorWithDesignatedOcspCheck.validate(Tokens.SIGNED);
        } catch (TokenValidationException e) {
            assertThat(e).isInstanceOf(UserCertificateRevokedException.class);
        }
    }

    @Test
    void testTokenCertRsaExpired() {
        assertThatThrownBy(() -> validator.validate(Tokens.TOKEN_CERT_RSA_EXIPRED))
            .isInstanceOf(CertificateExpiredException.class)
            .hasMessageStartingWith("User certificate has expired");
    }

    @Test
    void testTokenCertEcdsaExpired() {
        assertThatThrownBy(() -> validator.validate(Tokens.TOKEN_CERT_ECDSA_EXIPRED))
            .isInstanceOf(CertificateExpiredException.class)
            .hasMessageStartingWith("User certificate has expired");
    }

}
