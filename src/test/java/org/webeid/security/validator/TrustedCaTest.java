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
import org.webeid.security.exceptions.UserCertificateNotTrustedException;
import org.webeid.security.testutil.AbstractTestWithMockedDateAndCorrectNonce;
import org.webeid.security.testutil.Tokens;

import java.security.cert.CertificateException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.webeid.security.testutil.AuthTokenValidators.getAuthTokenValidatorWithWrongTrustedCA;

public class TrustedCaTest extends AbstractTestWithMockedDateAndCorrectNonce {

    private AuthTokenValidator validator;

    @Override
    @BeforeEach
    public void setup() {
        super.setup();
        try {
            validator = getAuthTokenValidatorWithWrongTrustedCA(cache);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void detectUntrustedUserCertificate() {
        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(UserCertificateNotTrustedException.class);
    }

}
