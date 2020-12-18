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

package org.webeid.security.validator.validators;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.webeid.security.exceptions.SiteCertificateFingerprintValidationException;
import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.validator.AuthTokenValidatorData;

public final class SiteCertificateFingerprintValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SiteCertificateFingerprintValidator.class);

    private final String expectedSiteCertificateFingerprint;

    public SiteCertificateFingerprintValidator(String expectedSiteCertificateFingerprint) {
        this.expectedSiteCertificateFingerprint = expectedSiteCertificateFingerprint;
    }

    /**
     * Validates that the site certificate fingerprint from the authentication token matches with
     * the configured site certificate fingerprint.
     *
     * @param actualTokenData authentication token data that contains the site fingerprint from authentication token
     * @throws TokenValidationException when fingerprints don't match
     */
    public void validateSiteCertificateFingerprint(AuthTokenValidatorData actualTokenData) throws TokenValidationException {
        if (!expectedSiteCertificateFingerprint.equals(actualTokenData.getSiteCertificateFingerprint())) {
            throw new SiteCertificateFingerprintValidationException();
        }
        LOG.debug("Site certificate fingerprint is equal to expected fingerprint.");
    }
}
