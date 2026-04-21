// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.ocsp.protocol.OcspResponseValidator;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
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
import java.util.Set;


import static eu.webeid.security.certificate.CertificateValidator.requireCertificateIsValidOnDate;

public class FallbackOcspService implements OcspService {

    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    private final URI url;
    private final boolean supportsNonce;
    private final X509Certificate trustedResponderCertificate;
    private final X509Certificate issuerCertificate;
    private final FallbackOcspService nextFallback;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private final Duration maxThisUpdateAge;
    private final Duration maxNextUpdateAge;

    public FallbackOcspService(FallbackOcspServiceConfiguration configuration) {
        this.url = configuration.getAccessLocation();
        this.supportsNonce = configuration.doesSupportNonce();
        this.trustedResponderCertificate = configuration.getResponderCertificate();
        this.issuerCertificate = configuration.getIssuerCertificate();
        this.nextFallback = configuration.getNextFallbackConfiguration() != null
            ? new FallbackOcspService(configuration.getNextFallbackConfiguration())
            : null;
        this.trustedCACertificateAnchors = configuration.getTrustedCACertificateAnchors();
        this.trustedCACertificateCertStore = configuration.getTrustedCACertificateCertStore();
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
    public void validateResponderCertificate(X509CertificateHolder cert, X509Certificate issuerCertificate, Date now) throws AuthTokenException {
        try {
            Objects.requireNonNull(issuerCertificate, "issuerCertificate");
            if (!this.issuerCertificate.equals(issuerCertificate)) {
                throw new OCSPCertificateException("Fallback OCSP service is not configured for the subject certificate's issuer");
            }
            final X509Certificate responderCertificate = certificateConverter.getCertificate(cert);
            requireCertificateIsValidOnDate(responderCertificate, now, "Fallback OCSP responder");
            if (trustedResponderCertificate != null) {
                validatePinnedResponderCertificate(responderCertificate);
            } else {
                validateResponderCertificateAgainstTrustedCa(responderCertificate, issuerCertificate, now);
            }
        } catch (GeneralSecurityException e) {
            throw new OCSPCertificateException("Invalid responder certificate", e);
        }
    }

    private void validatePinnedResponderCertificate(X509Certificate responderCertificate) throws OCSPCertificateException {
        // Certificate extensions (Basic Constraints, Key Usage, Extended Key Usage) are validated at
        // configuration time in FallbackOcspServiceConfiguration. Since equals() compares the full DER
        // encoding, a matching certificate is guaranteed to have the same validated extensions.
        // Certificate pinning is implemented simply by comparing the certificates or their public keys,
        // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
        if (!trustedResponderCertificate.equals(responderCertificate)) {
            throw new OCSPCertificateException("Responder certificate from the OCSP response is not equal to " +
                "the configured fallback OCSP responder certificate");
        }
    }

    private void validateResponderCertificateAgainstTrustedCa(X509Certificate responderCertificate, X509Certificate issuerCertificate, Date now) throws AuthTokenException, GeneralSecurityException {
        if (!responderCertificate.equals(issuerCertificate)) {
            OcspResponseValidator.validateBasicConstraintsNotCA(responderCertificate);
            OcspResponseValidator.validateKeyUsageDigitalSignature(responderCertificate);
            OcspResponseValidator.validateKeyUsageNotCertificateSigning(responderCertificate);
            OcspResponseValidator.validateExtendedKeyUsageOcspSigning(responderCertificate);
            // A delegated OCSP signer must be issued directly by the CA whose certificate status was requested.
            if (!responderCertificate.getIssuerX500Principal().equals(issuerCertificate.getSubjectX500Principal())) {
                throw new OCSPCertificateException("Fallback OCSP responder is not issued by the subject certificate's issuer");
            }
            responderCertificate.verify(issuerCertificate.getPublicKey());
        }
        CertificateValidator.validateCertificateTrustAndRevocation(
            responderCertificate,
            trustedCACertificateAnchors,
            trustedCACertificateCertStore,
            now,
            RevocationMode.DISABLED,
            null,
            null,
            false
        );
    }

    public FallbackOcspService getNextFallback() {
        return nextFallback;
    }
}
