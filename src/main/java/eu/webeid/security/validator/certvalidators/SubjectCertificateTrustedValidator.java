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
import eu.webeid.security.exceptions.AuthTokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import eu.webeid.security.exceptions.CertificateNotTrustedException;
import eu.webeid.security.util.DateAndTime;

import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

public final class SubjectCertificateTrustedValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificateTrustedValidator.class);

    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private X509Certificate subjectCertificateIssuerCertificate;

    public SubjectCertificateTrustedValidator(Set<TrustAnchor> trustedCACertificateAnchors, CertStore trustedCACertificateCertStore) {
        this.trustedCACertificateAnchors = trustedCACertificateAnchors;
        this.trustedCACertificateCertStore = trustedCACertificateCertStore;
    }

    /**
     * Validates that the user certificate from the authentication token is signed by a trusted certificate authority.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws CertificateNotTrustedException when user certificate is not signed by a trusted CA.
     */
    public void validateCertificateTrusted(X509Certificate subjectCertificate) throws AuthTokenException {
        // Use the clock instance so that the date can be mocked in tests.
        final Date now = DateAndTime.DefaultClock.INSTANCE.now();
        subjectCertificateIssuerCertificate = CertificateValidator.validateIsSignedByTrustedCA(
            subjectCertificate,
            trustedCACertificateAnchors,
            trustedCACertificateCertStore,
            now
        );
        LOG.debug("Subject certificate is signed by a trusted CA");
    }

    public X509Certificate getSubjectCertificateIssuerCertificate() {
        return subjectCertificateIssuerCertificate;
    }
}
