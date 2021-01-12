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

import org.junit.jupiter.api.Test;
import org.webeid.security.exceptions.SiteCertificateFingerprintValidationException;
import org.webeid.security.testutil.AbstractTestWithMockedDateAndCorrectNonce;
import org.webeid.security.testutil.Tokens;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.webeid.security.testutil.AuthTokenValidators.getAuthTokenValidator;

class FingerprintTest extends AbstractTestWithMockedDateAndCorrectNonce {

    @Test
    void validateFingerprint() throws Exception {
        final AuthTokenValidator validator = getAuthTokenValidator(cache,
            "urn:cert:sha-256:6f0df244e4a856b94b3b3b47582a0a51a32d674dbc7107211ed23d4bec6d9c72");
        assertThatCode(() -> validator.validate(Tokens.SIGNED))
            .doesNotThrowAnyException();
    }

    @Test
    void validateInvalidFingerprint() throws Exception {
        final AuthTokenValidator validator = getAuthTokenValidator(cache,
            "abcde6f0df244e4a856b94b3b3b47582a0a51a32d674dbc7107211ed23d4bec6d9c72");
        assertThatThrownBy(() -> validator.validate(Tokens.SIGNED))
            .isInstanceOf(SiteCertificateFingerprintValidationException.class);
    }

    @Test
    void testMismatchingSiteCertificateFingerprint() throws Exception {
        final AuthTokenValidator validator = getAuthTokenValidator(cache,
            "urn:cert:sha-256:6f0df244e4a856b94b3b3b47582a0a51a32d674dbc7107211ed23d4bec6d9c72");
        assertThatThrownBy(() -> validator.validate(Tokens.MISMATCHING_SITE_CERTIFICATE_FINGERPRINT))
            .isInstanceOf(SiteCertificateFingerprintValidationException.class);
    }

}
