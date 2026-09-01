// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotTrustedException;
import eu.webeid.security.exceptions.CertificateNotYetValidException;
import eu.webeid.security.util.DateAndTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
     * Checks that the user certificate from the authentication token is valid and signed by
     * a trusted certificate authority. Also checks the validity of the user certificate's
     * trusted CA certificate.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws CertificateNotTrustedException when user certificate is not signed by a trusted CA
     * @throws CertificateNotYetValidException when a CA certificate in the chain or the user certificate is not yet valid
     * @throws CertificateExpiredException when a CA certificate in the chain or the user certificate is expired
     */
    public void validateCertificateTrusted(X509Certificate subjectCertificate) throws AuthTokenException {
        // Use the clock instance so that the date can be mocked in tests.
        final Date now = DateAndTime.DefaultClock.getInstance().now();
        subjectCertificateIssuerCertificate = CertificateValidator.validateIsSignedByTrustedCA(
            subjectCertificate,
            trustedCACertificateAnchors,
            trustedCACertificateCertStore,
            now
        );
        LOG.debug("Subject certificate is valid and signed by a trusted CA");
    }

    public X509Certificate getSubjectCertificateIssuerCertificate() {
        return subjectCertificateIssuerCertificate;
    }
}
