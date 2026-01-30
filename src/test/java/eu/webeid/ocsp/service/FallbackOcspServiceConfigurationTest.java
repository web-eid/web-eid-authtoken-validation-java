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

class FallbackOcspServiceConfigurationTest {

    @Test
    void whenCallerMutatesCollections_thenConfigurationRemainsUnchanged() throws Exception {
        final TrustAnchor anchor = new TrustAnchor(getTestEsteid2018CA(), null);
        final Set<TrustAnchor> anchors = new HashSet<>(Set.of(anchor));
        final FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
                URI.create("http://fallback.ocsp.test"),
                null,
                true,
                null,
                getTestEsteid2018CA(),
                anchors,
                CertificateValidator.buildCertStoreFromCertificates(List.of(getTestEsteid2018CA())));

        anchors.clear();

        assertThat(configuration.getTrustedCACertificateAnchors()).containsExactly(anchor);
        assertThatThrownBy(() -> configuration.getTrustedCACertificateAnchors().clear()).isInstanceOf(UnsupportedOperationException.class);
    }
}
