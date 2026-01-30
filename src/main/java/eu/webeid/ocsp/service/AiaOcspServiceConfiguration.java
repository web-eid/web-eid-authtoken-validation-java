// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import org.bouncycastle.asn1.x500.X500Name;

import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;

public class AiaOcspServiceConfiguration {

    private final Collection<X500Name> nonceDisabledIssuerDNs;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;

    public AiaOcspServiceConfiguration(Collection<X500Name> nonceDisabledIssuerDNs, Set<TrustAnchor> trustedCACertificateAnchors, CertStore trustedCACertificateCertStore) {
        this.nonceDisabledIssuerDNs = Set.copyOf(nonceDisabledIssuerDNs);
        this.trustedCACertificateAnchors = Set.copyOf(trustedCACertificateAnchors);
        this.trustedCACertificateCertStore = Objects.requireNonNull(trustedCACertificateCertStore);
    }

    public Collection<X500Name> getNonceDisabledIssuerDNs() {
        return nonceDisabledIssuerDNs;
    }

    public Set<TrustAnchor> getTrustedCACertificateAnchors() {
        return trustedCACertificateAnchors;
    }

    public CertStore getTrustedCACertificateCertStore() {
        return trustedCACertificateCertStore;
    }

}
