// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.security.certificate.CertificateValidator;
import org.junit.jupiter.api.Test;

import java.net.URI;
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
        final URI responder = URI.create("http://ocsp.example");
        final Set<URI> nonceDisabledUrls = new HashSet<>(Set.of(responder));
        final TrustAnchor anchor = new TrustAnchor(getTestEsteid2018CA(), null);
        final Set<TrustAnchor> anchors = new HashSet<>(Set.of(anchor));
        final AiaOcspServiceConfiguration configuration = new AiaOcspServiceConfiguration(
                nonceDisabledUrls, anchors, CertificateValidator.buildCertStoreFromCertificates(List.of(getTestEsteid2018CA())));

        nonceDisabledUrls.clear();
        anchors.clear();

        assertThat(configuration.getNonceDisabledOcspUrls()).containsExactly(responder);
        assertThat(configuration.getTrustedCACertificateAnchors()).containsExactly(anchor);
        assertThatThrownBy(() -> configuration.getNonceDisabledOcspUrls().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> configuration.getTrustedCACertificateAnchors().clear()).isInstanceOf(UnsupportedOperationException.class);
    }
}
