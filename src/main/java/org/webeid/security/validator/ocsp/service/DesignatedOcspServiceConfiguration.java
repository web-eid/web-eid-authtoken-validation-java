package org.webeid.security.validator.ocsp.service;

import org.webeid.security.exceptions.OCSPCertificateException;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Objects;

import static org.webeid.security.validator.ocsp.OcspUtils.validateHasSigningExtension;

public class DesignatedOcspServiceConfiguration {

    private final URI ocspServiceUrl;
    private final X509Certificate responderCertificate;
    private final boolean doesSupportNonce;

    public DesignatedOcspServiceConfiguration(URI ocspServiceUrl, X509Certificate responderCertificate, boolean doesSupportNonce) throws OCSPCertificateException {
        this.ocspServiceUrl = Objects.requireNonNull(ocspServiceUrl, "OCSP service URL");
        this.responderCertificate = Objects.requireNonNull(responderCertificate, "OCSP responder certificate");
        validateHasSigningExtension(responderCertificate);
        this.doesSupportNonce = doesSupportNonce;
    }

    public DesignatedOcspServiceConfiguration(URI ocspServiceUrl, X509Certificate responderCertificate) throws OCSPCertificateException {
        this(ocspServiceUrl, responderCertificate, true);
    }

    public URI getOcspServiceUrl() {
        return ocspServiceUrl;
    }

    public X509Certificate getResponderCertificate() {
        return responderCertificate;
    }

    public boolean doesSupportNonce() {
        return doesSupportNonce;
    }
}
