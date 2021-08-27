package org.webeid.security.validator.ocsp.service;

import org.webeid.security.exceptions.JceException;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;

import static org.webeid.security.certificate.CertificateValidator.*;

public class AiaOcspResponderConfiguration {

    private final URI responderUrl;
    private final boolean doesSupportNonce;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;

    public AiaOcspResponderConfiguration(URI responderUrl, X509Certificate responderTrustedCACertificate, boolean doesSupportNonce) throws JceException {
        this.responderUrl = responderUrl;
        this.trustedCACertificateAnchors = buildTrustAnchorsFromCertificate(responderTrustedCACertificate);
        this.trustedCACertificateCertStore = buildCertStoreFromCertificate(responderTrustedCACertificate);
        this.doesSupportNonce = doesSupportNonce;
    }

    public AiaOcspResponderConfiguration(URI responderUrl, X509Certificate responderTrustedCACertificate) throws JceException {
        this(responderUrl, responderTrustedCACertificate, true);
    }

    public boolean doesSupportNonce() {
        return doesSupportNonce;
    }

    public URI getResponderUrl() {
        return responderUrl;
    }

    public Set<TrustAnchor> getTrustedCACertificateAnchors() {
        return trustedCACertificateAnchors;
    }

    public CertStore getTrustedCACertificateCertStore() {
        return trustedCACertificateCertStore;
    }
}
