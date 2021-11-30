/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

import eu.webeid.security.certificate.CertificateValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.util.DateAndTime;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

public final class SubjectCertificateExpiryValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificateExpiryValidator.class);

    private final Set<TrustAnchor> trustedCACertificateAnchors;

    public SubjectCertificateExpiryValidator(Set<TrustAnchor> trustedCACertificateAnchors) {
        this.trustedCACertificateAnchors = trustedCACertificateAnchors;
    }

    /**
     * Checks the validity of the user certificate from the authentication token
     * and the validity of trusted CA certificates.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws AuthTokenException when a CA certificate or the user certificate is expired or not yet valid
     */
    public void validateCertificateExpiry(X509Certificate subjectCertificate) throws AuthTokenException {
        // Use the clock instance so that the date can be mocked in tests.
        final Date now = DateAndTime.DefaultClock.INSTANCE.now();
        CertificateValidator.trustedCACertificatesAreValidOnDate(trustedCACertificateAnchors, now);
        LOG.debug("CA certificates are valid.");
        CertificateValidator.certificateIsValidOnDate(subjectCertificate, now, "User");
        LOG.debug("User certificate is valid.");
    }

}
