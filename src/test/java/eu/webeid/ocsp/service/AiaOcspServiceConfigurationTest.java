// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.security.certificate.CertificateValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;

import java.security.cert.TrustAnchor;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiaOcspServiceConfigurationTest {

    @Test
    void whenCallerMutatesCollections_thenConfigurationRemainsUnchanged() throws Exception {
        final X500Name issuerDN = new X500Name("CN=TEST of ESTEID2018, O=SK ID Solutions AS, C=EE");
        final Set<X500Name> nonceDisabledIssuerDNs = new HashSet<>(Set.of(issuerDN));
        final TrustAnchor anchor = new TrustAnchor(getTestEsteid2018CA(), null);
        final Set<TrustAnchor> anchors = new HashSet<>(Set.of(anchor));
        final AiaOcspServiceConfiguration configuration = new AiaOcspServiceConfiguration(
                nonceDisabledIssuerDNs, anchors, CertificateValidator.buildCertStoreFromCertificates(List.of(getTestEsteid2018CA())));

        nonceDisabledIssuerDNs.clear();
        anchors.clear();

        assertThat(configuration.getNonceDisabledIssuerDNs()).containsExactly(issuerDN);
        assertThat(configuration.getTrustedCACertificateAnchors()).containsExactly(anchor);
        assertThatThrownBy(() -> configuration.getNonceDisabledIssuerDNs().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> configuration.getTrustedCACertificateAnchors().clear()).isInstanceOf(UnsupportedOperationException.class);
    }
}
