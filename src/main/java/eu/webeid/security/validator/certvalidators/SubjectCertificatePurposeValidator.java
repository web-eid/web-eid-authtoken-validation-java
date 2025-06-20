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

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.UserCertificateMissingPurposeException;
import eu.webeid.security.exceptions.UserCertificateParseException;
import eu.webeid.security.exceptions.UserCertificateWrongPurposeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

public final class SubjectCertificatePurposeValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificatePurposeValidator.class);
    private static final int KEY_USAGE_DIGITAL_SIGNATURE = 0;
    private static final String EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION = "1.3.6.1.5.5.7.3.2";
    /**
     * Validates that the purpose of the user certificate from the authentication token contains client authentication.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws AuthTokenException when the purpose of certificate does not contain client authentication
     */
    public static void validateCertificatePurpose(X509Certificate subjectCertificate) throws AuthTokenException {
        try {
            final boolean[] keyUsage = subjectCertificate.getKeyUsage();
            if (keyUsage == null) {
                throw new UserCertificateMissingPurposeException();
            }
            if (!keyUsage[KEY_USAGE_DIGITAL_SIGNATURE]) {
                throw new UserCertificateWrongPurposeException();
            }
            final List<String> usages = subjectCertificate.getExtendedKeyUsage();
            if (usages == null || usages.isEmpty()) {
                // Digital Signature extension present, but Extended Key Usage extension not present,
                // assume it is an authentication certificate (e.g. Luxembourg eID).
                LOG.debug("User certificate has Digital Signature key usage and no Extended Key Usage extension, this means that it can be used for client authentication.");
                return;
            }
            if (!usages.contains(EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION)) {
                throw new UserCertificateWrongPurposeException();
            }
        } catch (CertificateParsingException e) {
            throw new UserCertificateParseException(e);
        }
        LOG.debug("User certificate can be used for client authentication.");
    }

    private SubjectCertificatePurposeValidator() {
        throw new IllegalStateException("Functional class");
    }

}
