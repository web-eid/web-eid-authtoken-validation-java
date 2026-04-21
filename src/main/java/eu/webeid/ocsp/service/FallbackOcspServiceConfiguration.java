// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.ocsp.protocol.OcspResponseValidator;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;

import static eu.webeid.security.util.DateAndTime.requirePositiveDuration;

public class FallbackOcspServiceConfiguration {

    private final URI accessLocation;
    private final X509Certificate responderCertificate;
    private final boolean doesSupportNonce;
    private final FallbackOcspServiceConfiguration nextFallbackConfiguration;
    private final X509Certificate issuerCertificate;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private final Duration maxThisUpdateAge;
    private final Duration maxNextUpdateAge;

    public FallbackOcspServiceConfiguration(URI accessLocation, X509Certificate responderCertificate,
                                            boolean doesSupportNonce,
                                            FallbackOcspServiceConfiguration nextFallbackConfiguration,
                                            X509Certificate issuerCertificate, Set<TrustAnchor> trustedCACertificateAnchors,
                                            CertStore trustedCACertificateCertStore,
                                            Duration maxThisUpdateAge, Duration maxNextUpdateAge) throws OCSPCertificateException {
        this.accessLocation = Objects.requireNonNull(accessLocation, "Fallback OCSP service access location");
        this.responderCertificate = responderCertificate;
        if (responderCertificate != null) {
            OcspResponseValidator.validateBasicConstraintsNotCA(responderCertificate);
            OcspResponseValidator.validateKeyUsageDigitalSignature(responderCertificate);
            OcspResponseValidator.validateKeyUsageNotCertificateSigning(responderCertificate);
            OcspResponseValidator.validateExtendedKeyUsageOcspSigning(responderCertificate);
        }
        this.doesSupportNonce = doesSupportNonce;
        this.nextFallbackConfiguration = nextFallbackConfiguration;
        this.issuerCertificate = Objects.requireNonNull(issuerCertificate, "issuerCertificate");
        this.trustedCACertificateAnchors = Set.copyOf(Objects.requireNonNull(trustedCACertificateAnchors, "trustedCACertificateAnchors"));
        this.trustedCACertificateCertStore = Objects.requireNonNull(trustedCACertificateCertStore, "trustedCACertificateCertStore");
        this.maxThisUpdateAge = requirePositiveDuration(maxThisUpdateAge, "maxThisUpdateAge");
        this.maxNextUpdateAge = requirePositiveDuration(maxNextUpdateAge, "maxNextUpdateAge");
    }

    public URI getAccessLocation() {
        return accessLocation;
    }

    public X509Certificate getResponderCertificate() {
        return responderCertificate;
    }

    public boolean doesSupportNonce() {
        return doesSupportNonce;
    }

    public FallbackOcspServiceConfiguration getNextFallbackConfiguration() {
        return nextFallbackConfiguration;
    }

    public X509Certificate getIssuerCertificate() {
        return issuerCertificate;
    }

    public Set<TrustAnchor> getTrustedCACertificateAnchors() {
        return trustedCACertificateAnchors;
    }

    public CertStore getTrustedCACertificateCertStore() {
        return trustedCACertificateCertStore;
    }

    public Duration getMaxThisUpdateAge() {
        return maxThisUpdateAge;
    }

    public Duration getMaxNextUpdateAge() {
        return maxNextUpdateAge;
    }
}
