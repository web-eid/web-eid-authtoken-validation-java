/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package eu.webeid.ocsp.service;

import eu.webeid.security.certificate.CertificateValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static eu.webeid.ocsp.protocol.IssuerDistinguishedName.getIssuerDistinguishedName;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getMariliisEsteid2015Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2015CA;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.Certificates.getDemoEsteidSk2018AiaOcspResponder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Unit tests for the {@link AiaOcspService} behaviour introduced in commit e2bd57e3:
 * nonce support is now keyed on the certificate's issuer distinguished name (previously the OCSP URL),
 * and the service carries an optional {@link FallbackOcspService}.
 */
class AiaOcspServiceTest {

    private static final URI ESTEID2018_AIA_OCSP_URI = URI.create("http://aia.demo.sk.ee/esteid2018");
    private static final URI ESTEID2015_AIA_OCSP_URI = URI.create("http://aia.demo.sk.ee/esteid2015");
    private static final URI FALLBACK_URI = URI.create("http://fallback.ocsp.test");

    private static Set<TrustAnchor> trustedCaAnchors;
    private static CertStore trustedCaCertStore;
    private static X509Certificate esteid2018UserCert;
    private static X509Certificate esteid2015UserCert;
    private static X500Name esteid2018IssuerDN;
    private static X500Name esteid2015IssuerDN;

    @BeforeAll
    static void setUpFixtures() throws Exception {
        List<X509Certificate> trustedCaCertificates = List.of(getTestEsteid2018CA(), getTestEsteid2015CA());
        trustedCaAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(trustedCaCertificates);
        trustedCaCertStore = CertificateValidator.buildCertStoreFromCertificates(trustedCaCertificates);
        esteid2018UserCert = getJaakKristjanEsteid2018Cert();
        esteid2015UserCert = getMariliisEsteid2015Cert();
        esteid2018IssuerDN = getIssuerDistinguishedName(esteid2018UserCert);
        esteid2015IssuerDN = getIssuerDistinguishedName(esteid2015UserCert);
    }

    private static AiaOcspServiceConfiguration configurationWithNonceDisabledFor(X500Name... nonceDisabledIssuerDNs) {
        return new AiaOcspServiceConfiguration(Set.of(nonceDisabledIssuerDNs), trustedCaAnchors, trustedCaCertStore);
    }

    @Test
    void whenIssuerDnIsInNonceDisabledSet_thenDoesNotSupportNonce() throws Exception {
        AiaOcspServiceConfiguration configuration = configurationWithNonceDisabledFor(esteid2015IssuerDN);

        AiaOcspService service = new AiaOcspService(configuration, esteid2015UserCert, null);

        assertThat(service.getAccessLocation()).isEqualTo(ESTEID2015_AIA_OCSP_URI);
        assertThat(service.doesSupportNonce()).isFalse();
    }

    @Test
    void whenIssuerDnIsNotInNonceDisabledSet_thenSupportsNonce() throws Exception {
        // Only the ESTEID-SK 2015 issuer is nonce-disabled, so a certificate from the 2018 issuer must still support nonce.
        AiaOcspServiceConfiguration configuration = configurationWithNonceDisabledFor(esteid2015IssuerDN);

        AiaOcspService service = new AiaOcspService(configuration, esteid2018UserCert, null);

        assertThat(service.getAccessLocation()).isEqualTo(ESTEID2018_AIA_OCSP_URI);
        assertThat(service.doesSupportNonce()).isTrue();
    }

    @Test
    void whenFallbackServiceProvided_thenGetFallbackServiceReturnsIt() throws Exception {
        AiaOcspServiceConfiguration configuration = configurationWithNonceDisabledFor();
        FallbackOcspServiceConfiguration fallbackConfiguration = new FallbackOcspServiceConfiguration(
            FALLBACK_URI, getDemoEsteidSk2018AiaOcspResponder(), true,
            null, esteid2018IssuerDN, trustedCaAnchors, trustedCaCertStore);
        FallbackOcspService fallback = new FallbackOcspService(fallbackConfiguration);

        AiaOcspService service = new AiaOcspService(configuration, esteid2018UserCert, fallback);

        assertThat(service.getFallbackService()).containsSame(fallback);
        assertThat(service.getFallbackService().get().getAccessLocation()).isEqualTo(FALLBACK_URI);
    }

    @Test
    void whenFallbackServiceIsNull_thenGetFallbackServiceIsEmpty() throws Exception {
        AiaOcspServiceConfiguration configuration = configurationWithNonceDisabledFor();

        AiaOcspService service = new AiaOcspService(configuration, esteid2018UserCert, null);

        assertThat(service.getFallbackService()).isEmpty();
    }

    @Test
    void whenCertificateIsNull_thenThrows() {
        AiaOcspServiceConfiguration configuration = configurationWithNonceDisabledFor();

        assertThatExceptionOfType(NullPointerException.class)
            .isThrownBy(() -> new AiaOcspService(configuration, null, null));
    }
}
