// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.ocsp.exceptions.UserCertificateOCSPException;
import eu.webeid.ocsp.protocol.OcspResponseValidator;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import static eu.webeid.ocsp.protocol.IssuerDistinguishedName.getIssuerDistinguishedName;
import static eu.webeid.ocsp.protocol.OcspUrl.getOcspUri;

/**
 * An OCSP service that uses the responders from the Certificates' Authority Information Access (AIA) extension.
 */
public class AiaOcspService implements OcspService {

    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private final URI url;
    private final boolean supportsNonce;
    private final FallbackOcspService fallbackOcspService;
    private final Duration maxThisUpdateAge;
    private final Duration maxNextUpdateAge;

    public AiaOcspService(AiaOcspServiceConfiguration configuration, X509Certificate certificate, FallbackOcspService fallbackOcspService) throws UserCertificateOCSPException {
        Objects.requireNonNull(configuration);
        this.trustedCACertificateAnchors = configuration.getTrustedCACertificateAnchors();
        this.trustedCACertificateCertStore = configuration.getTrustedCACertificateCertStore();
        this.url = getOcspAiaUrlFromCertificate(Objects.requireNonNull(certificate));
        this.fallbackOcspService = fallbackOcspService;
        X500Name issuerDN = getIssuerDistinguishedName(certificate);
        this.supportsNonce = !configuration.getNonceDisabledIssuerDNs().contains(issuerDN);
        this.maxThisUpdateAge = configuration.getMaxThisUpdateAge();
        this.maxNextUpdateAge = configuration.getMaxNextUpdateAge();
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
    public Duration getMaxThisUpdateAge() {
        return maxThisUpdateAge;
    }

    @Override
    public Duration getMaxNextUpdateAge() {
        return maxNextUpdateAge;
    }

    @Override
    public Optional<FallbackOcspService> getFallbackService() {
        return Optional.ofNullable(fallbackOcspService);
    }

    @Override
    public void validateResponderCertificate(X509CertificateHolder cert, X509Certificate issuerCertificate, Date now) throws AuthTokenException {
        try {
            final X509Certificate certificate = certificateConverter.getCertificate(cert);
            CertificateValidator.requireCertificateIsValidOnDate(certificate, now, "AIA OCSP responder");
            if (!certificate.equals(issuerCertificate)) {
                OcspResponseValidator.validateBasicConstraintsNotCA(certificate);
                OcspResponseValidator.validateKeyUsageDigitalSignature(certificate);
                OcspResponseValidator.validateKeyUsageNotCertificateSigning(certificate);
                OcspResponseValidator.validateExtendedKeyUsageOcspSigning(certificate);
                // A delegated OCSP signer must be issued directly by the CA whose certificate status was requested.
                if (!certificate.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal())) {
                    throw new OCSPCertificateException("AIA OCSP responder is not issued by the subject certificate's issuer");
                }
                certificate.verify(issuerCertificate.getPublicKey());
            }
            CertificateValidator.validateCertificateTrustAndRevocation(
                    certificate,
                    trustedCACertificateAnchors,
                    trustedCACertificateCertStore,
                    now,
                    RevocationMode.DISABLED,
                    null,
                    null,
                    false
            );
        } catch (GeneralSecurityException e) {
            throw new OCSPCertificateException("Invalid responder certificate", e);
        }
    }

    private static URI getOcspAiaUrlFromCertificate(X509Certificate certificate) throws UserCertificateOCSPException {
        return getOcspUri(certificate).orElseThrow(() ->
            new UserCertificateOCSPException("Getting the AIA OCSP responder field from the certificate failed")
        );
    }

}
