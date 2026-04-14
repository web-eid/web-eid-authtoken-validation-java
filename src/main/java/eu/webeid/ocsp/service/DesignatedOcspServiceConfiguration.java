// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.ocsp.protocol.OcspResponseValidator;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;

public class DesignatedOcspServiceConfiguration {

    private final URI ocspServiceAccessLocation;
    private final X509Certificate responderCertificate;
    private final boolean doesSupportNonce;
    private final Set<X509Certificate> supportedIssuers;

    /**
     * Configuration of a designated OCSP service.
     *
     * @param ocspServiceAccessLocation the URL where the service is located
     * @param responderCertificate the service's OCSP responder certificate
     * @param supportedCertificateIssuers the certificate issuers supported by the service
     * @param doesSupportNonce true if the service supports the OCSP protocol nonce extension
     * @throws OCSPCertificateException when the responder certificate lacks OCSP signing usage
     */
    public DesignatedOcspServiceConfiguration(URI ocspServiceAccessLocation, X509Certificate responderCertificate, Collection<X509Certificate> supportedCertificateIssuers, boolean doesSupportNonce) throws OCSPCertificateException {
        this.ocspServiceAccessLocation = Objects.requireNonNull(ocspServiceAccessLocation, "OCSP service access location");
        this.responderCertificate = Objects.requireNonNull(responderCertificate, "OCSP responder certificate");
        this.supportedIssuers = Set.copyOf(Objects.requireNonNull(supportedCertificateIssuers, "supported issuers"));
        OcspResponseValidator.validateBasicConstraintsNotCA(responderCertificate);
        OcspResponseValidator.validateKeyUsageDigitalSignature(responderCertificate);
        OcspResponseValidator.validateKeyUsageNotCertificateSigning(responderCertificate);
        OcspResponseValidator.validateExtendedKeyUsageOcspSigning(responderCertificate);
        this.doesSupportNonce = doesSupportNonce;
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

    public boolean supportsIssuer(X509Certificate issuerCertificate) {
        return supportedIssuers.contains(Objects.requireNonNull(issuerCertificate, "issuerCertificate"));
    }
}
