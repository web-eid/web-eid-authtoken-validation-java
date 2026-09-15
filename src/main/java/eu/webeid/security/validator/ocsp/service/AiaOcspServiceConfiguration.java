// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.ocsp.service;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;

public class AiaOcspServiceConfiguration {

    private final Collection<URI> nonceDisabledOcspUrls;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;

    public AiaOcspServiceConfiguration(Collection<URI> nonceDisabledOcspUrls, Set<TrustAnchor> trustedCACertificateAnchors, CertStore trustedCACertificateCertStore) {
        this.nonceDisabledOcspUrls = Objects.requireNonNull(nonceDisabledOcspUrls);
        this.trustedCACertificateAnchors = Objects.requireNonNull(trustedCACertificateAnchors);
        this.trustedCACertificateCertStore = Objects.requireNonNull(trustedCACertificateCertStore);
    }

    public Collection<URI> getNonceDisabledOcspUrls() {
        return nonceDisabledOcspUrls;
    }

    public Set<TrustAnchor> getTrustedCACertificateAnchors() {
        return trustedCACertificateAnchors;
    }

    public CertStore getTrustedCACertificateCertStore() {
        return trustedCACertificateCertStore;
    }

}
