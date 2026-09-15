// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.ocsp.service;

import eu.webeid.security.validator.ocsp.OcspResponseValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import eu.webeid.security.exceptions.OCSPCertificateException;

import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;

public class DesignatedOcspServiceConfiguration {

    private final URI ocspServiceAccessLocation;
    private final X509Certificate responderCertificate;
    private final boolean doesSupportNonce;
    private final Collection<X500Name> supportedIssuers;

    /**
     * Configuration of a designated OCSP service.
     *
     * @param ocspServiceAccessLocation the URL where the service is located
     * @param responderCertificate the service's OCSP responder certificate
     * @param supportedCertificateIssuers the certificate issuers supported by the service
     * @param doesSupportNonce true if the service supports the OCSP protocol nonce extension
     * @throws OCSPCertificateException when an error occurs while extracting issuer names from certificates
     */
    public DesignatedOcspServiceConfiguration(URI ocspServiceAccessLocation, X509Certificate responderCertificate, Collection<X509Certificate> supportedCertificateIssuers, boolean doesSupportNonce) throws OCSPCertificateException {
        this.ocspServiceAccessLocation = Objects.requireNonNull(ocspServiceAccessLocation, "OCSP service access location");
        this.responderCertificate = Objects.requireNonNull(responderCertificate, "OCSP responder certificate");
        this.supportedIssuers = getIssuerX500Names(Objects.requireNonNull(supportedCertificateIssuers, "supported issuers"));
        OcspResponseValidator.validateHasSigningExtension(responderCertificate);
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

    public boolean supportsIssuerOf(X509Certificate certificate) throws CertificateEncodingException {
        return supportedIssuers.contains(new JcaX509CertificateHolder(Objects.requireNonNull(certificate)).getIssuer());
    }

    private Collection<X500Name> getIssuerX500Names(Collection<X509Certificate> supportedIssuers) throws OCSPCertificateException {
        try {
            return supportedIssuers.stream()
                .map(this::getSubject)
                .collect(Collectors.toList());
        } catch (IllegalArgumentException e) {
            throw new OCSPCertificateException("Supported issuer list contains an invalid certificate", e.getCause());
        }
    }

    private X500Name getSubject(X509Certificate certificate) throws IllegalArgumentException {
        try {
            return new JcaX509CertificateHolder(certificate).getSubject();
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
