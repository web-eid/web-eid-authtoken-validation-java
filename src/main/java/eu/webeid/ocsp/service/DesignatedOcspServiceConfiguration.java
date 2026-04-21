// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.ocsp.protocol.OcspResponseValidator;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;

import static eu.webeid.security.util.DateAndTime.requirePositiveDuration;

public class DesignatedOcspServiceConfiguration {

    private final URI ocspServiceAccessLocation;
    private final X509Certificate responderCertificate;
    private final boolean doesSupportNonce;
    private final Set<X509Certificate> supportedIssuers;
    private final Duration maxThisUpdateAge;
    private final Duration maxNextUpdateAge;

    /**
     * Configuration of a designated OCSP service.
     *
     * @param ocspServiceAccessLocation the URL where the service is located
     * @param responderCertificate the service's OCSP responder certificate
     * @param supportedCertificateIssuers the certificate issuers supported by the service
     * @param doesSupportNonce true if the service supports the OCSP protocol nonce extension
     * @param maxThisUpdateAge the maximum age of the OCSP response's {@code thisUpdate} time, must be greater than zero
     * @param maxNextUpdateAge the maximum age of the OCSP response's {@code nextUpdate} time, must be greater than zero
     * @throws OCSPCertificateException when the responder certificate lacks OCSP signing usage
     */
    public DesignatedOcspServiceConfiguration(URI ocspServiceAccessLocation, X509Certificate responderCertificate, Collection<X509Certificate> supportedCertificateIssuers, boolean doesSupportNonce, Duration maxThisUpdateAge, Duration maxNextUpdateAge) throws OCSPCertificateException {
        this.ocspServiceAccessLocation = Objects.requireNonNull(ocspServiceAccessLocation, "OCSP service access location");
        this.responderCertificate = Objects.requireNonNull(responderCertificate, "OCSP responder certificate");
        this.supportedIssuers = Set.copyOf(Objects.requireNonNull(supportedCertificateIssuers, "supported issuers"));
        OcspResponseValidator.validateBasicConstraintsNotCA(responderCertificate);
        OcspResponseValidator.validateKeyUsageDigitalSignature(responderCertificate);
        OcspResponseValidator.validateKeyUsageNotCertificateSigning(responderCertificate);
        OcspResponseValidator.validateExtendedKeyUsageOcspSigning(responderCertificate);
        this.doesSupportNonce = doesSupportNonce;
        this.maxThisUpdateAge = requirePositiveDuration(maxThisUpdateAge, "maxThisUpdateAge");
        this.maxNextUpdateAge = requirePositiveDuration(maxNextUpdateAge, "maxNextUpdateAge");
    }

    public URI getOcspServiceAccessLocation() {
        return ocspServiceAccessLocation;
    }

    public X509Certificate getResponderCertificate() {
        return responderCertificate;
    }

    public boolean doesSupportNonce() {
        return doesSupportNonce;
    }

    public Duration getMaxThisUpdateAge() {
        return maxThisUpdateAge;
    }

    public Duration getMaxNextUpdateAge() {
        return maxNextUpdateAge;
    }

    public boolean supportsIssuer(X509Certificate issuerCertificate) {
        return supportedIssuers.contains(Objects.requireNonNull(issuerCertificate, "issuerCertificate"));
    }
}
