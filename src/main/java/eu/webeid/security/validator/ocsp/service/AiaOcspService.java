// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.ocsp.service;

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.OCSPCertificateException;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.validator.ocsp.OcspResponseValidator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Objects;
import java.util.Set;

import static eu.webeid.security.validator.ocsp.OcspUrl.getOcspUri;

/**
 * An OCSP service that uses the responders from the Certificates' Authority Information Access (AIA) extension.
 */
public class AiaOcspService implements OcspService {

    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private final URI url;
    private final boolean supportsNonce;

    public AiaOcspService(AiaOcspServiceConfiguration configuration, X509Certificate certificate) throws AuthTokenException {
        Objects.requireNonNull(configuration);
        this.trustedCACertificateAnchors = configuration.getTrustedCACertificateAnchors();
        this.trustedCACertificateCertStore = configuration.getTrustedCACertificateCertStore();
        this.url = getOcspAiaUrlFromCertificate(Objects.requireNonNull(certificate));
        this.supportsNonce = !configuration.getNonceDisabledOcspUrls().contains(this.url);
    }

    @Override
    public boolean doesSupportNonce() {
        return supportsNonce;
    }

    @Override
    public URI getAccessLocation() {
        return url;
    }

    @Override
    public void validateResponderCertificate(X509CertificateHolder cert, Date now) throws AuthTokenException {
        try {
            final X509Certificate certificate = certificateConverter.getCertificate(cert);
            CertificateValidator.certificateIsValidOnDate(certificate, now, "AIA OCSP responder");
            // Trusted certificates' validity has been already verified in validateCertificateExpiry().
            OcspResponseValidator.validateHasSigningExtension(certificate);
            CertificateValidator.validateIsSignedByTrustedCA(certificate, trustedCACertificateAnchors, trustedCACertificateCertStore, now);
        } catch (CertificateException e) {
            throw new OCSPCertificateException("Invalid responder certificate", e);
        }
    }

    private static URI getOcspAiaUrlFromCertificate(X509Certificate certificate) throws AuthTokenException {
        return getOcspUri(certificate).orElseThrow(() ->
            new UserCertificateOCSPCheckFailedException("Getting the AIA OCSP responder field from the certificate failed")
        );
    }

}
