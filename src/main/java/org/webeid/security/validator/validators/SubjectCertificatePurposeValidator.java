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

import io.jsonwebtoken.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.exceptions.UserCertificateMissingPurposeException;
import org.webeid.security.exceptions.UserCertificateParseException;
import org.webeid.security.exceptions.UserCertificateWrongPurposeException;
import org.webeid.security.validator.AuthTokenValidatorData;

import java.security.cert.CertificateParsingException;
import java.util.Date;
import java.util.List;

public final class SubjectCertificatePurposeValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificatePurposeValidator.class);
    private static final String EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION = "1.3.6.1.5.5.7.3.2";

    /**
     * Validates that the purpose of the user certificate from the authentication token contains client authentication.
     *
     * @param actualTokenData authentication token data that contains the user certificate
     * @throws TokenValidationException when the purpose of certificate does not contain client authentication
     */
    public static void validateCertificatePurpose(AuthTokenValidatorData actualTokenData) throws TokenValidationException {
        try {
            final List<String> usages = actualTokenData.getSubjectCertificate().getExtendedKeyUsage();
            if (usages == null || usages.isEmpty()) {
                throw new UserCertificateMissingPurposeException();
            }
            if (!usages.contains(EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION)) {
                throw new UserCertificateWrongPurposeException();
            }
            LOG.debug("User certificate can be used for client authentication.");
        } catch (CertificateParsingException e) {
            throw new UserCertificateParseException(e);
        }
    }

    private SubjectCertificatePurposeValidator() {
        throw new IllegalStateException("Functional class");
    }

    public static class DefaultClock implements Clock {

        public static final Clock INSTANCE = new DefaultClock();

        public Date now() {
            return new Date();
        }

    }
}
