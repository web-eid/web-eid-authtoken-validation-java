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

import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.security.certificate.CertificateValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import static eu.webeid.ocsp.OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE;
import static eu.webeid.ocsp.OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE;

import static eu.webeid.security.testutil.Certificates.getDemoEsteidSk2018AiaOcspResponder;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2015CA;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.Certificates.getTestSkOcspResponder2020;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class FallbackOcspServiceConfigurationTest {

    private static final URI FALLBACK_URI = URI.create("http://fallback.ocsp.test");
    private static final X500Name ISSUER_DN = new X500Name("CN=TEST of ESTEID-SK 2015, OID.2.5.4.97=NTREE-10747013, O=AS Sertifitseerimiskeskus, C=EE");

    private static Set<TrustAnchor> trustedCaAnchors;
    private static CertStore trustedCaCertStore;
    private static X509Certificate aiaOcspResponderCert;
    private static X509Certificate ocspResponder2020Cert;
    private static X509Certificate nonSigningUserCert;

    @BeforeAll
    static void setUpFixtures() throws Exception {
        List<X509Certificate> trustedCaCertificates = List.of(getTestEsteid2018CA(), getTestEsteid2015CA());
        trustedCaAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(trustedCaCertificates);
        trustedCaCertStore = CertificateValidator.buildCertStoreFromCertificates(trustedCaCertificates);
        // The DEMO AIA responder certificate satisfies every OCSP responder extension requirement.
        aiaOcspResponderCert = getDemoEsteidSk2018AiaOcspResponder();
        // TEST of SK OCSP RESPONDER 2020 carries no Key Usage extension at all.
        ocspResponder2020Cert = getTestSkOcspResponder2020();
        nonSigningUserCert = getJaakKristjanEsteid2018Cert();
    }

    @Test
    void whenAccessLocationIsNull_thenThrows() {
        assertThatNullPointerException()
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                null, null, true, null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
                DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE))
            .withMessage("Fallback OCSP service access location");
    }

    @Test
    void whenIssuerDnIsNull_thenThrows() {
        assertThatNullPointerException()
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, null, true, null, null, trustedCaAnchors, trustedCaCertStore,
                DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE))
            .withMessage("issuerDN");
    }

    @Test
    void whenTrustedCaAnchorsIsNull_thenThrows() {
        assertThatNullPointerException()
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, null, true, null, ISSUER_DN, null, trustedCaCertStore,
                DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE))
            .withMessage("trustedCACertificateAnchors");
    }

    @Test
    void whenTrustedCaCertStoreIsNull_thenThrows() {
        assertThatNullPointerException()
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, null, true, null, ISSUER_DN, trustedCaAnchors, null,
                DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE))
            .withMessage("trustedCACertificateCertStore");
    }

    @Test
    void whenMaxThisUpdateAgeIsNull_thenThrows() {
        assertThatNullPointerException()
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, null, true, null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
                null, DEFAULT_NEXT_UPDATE_AGE))
            .withMessage("maxThisUpdateAge must not be null");
    }

    @Test
    void whenMaxNextUpdateAgeIsNull_thenThrows() {
        assertThatNullPointerException()
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, null, true, null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
                DEFAULT_THIS_UPDATE_AGE, null))
            .withMessage("maxNextUpdateAge must not be null");
    }

    @Test
    void whenMaxThisUpdateAgeIsZero_thenThrows() {
        assertThatIllegalArgumentException()
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, null, true, null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
                Duration.ZERO, DEFAULT_NEXT_UPDATE_AGE))
            .withMessage("maxThisUpdateAge must be greater than zero");
    }

    @Test
    void whenMaxThisUpdateAgeIsNegative_thenThrows() {
        assertThatIllegalArgumentException()
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, null, true, null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
                Duration.ofMinutes(-1), DEFAULT_NEXT_UPDATE_AGE))
            .withMessage("maxThisUpdateAge must be greater than zero");
    }

    @Test
    void whenMaxNextUpdateAgeIsZero_thenThrows() {
        assertThatIllegalArgumentException()
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, null, true, null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
                DEFAULT_THIS_UPDATE_AGE, Duration.ZERO))
            .withMessage("maxNextUpdateAge must be greater than zero");
    }

    @Test
    void whenMaxNextUpdateAgeIsNegative_thenThrows() {
        assertThatIllegalArgumentException()
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, null, true, null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
                DEFAULT_THIS_UPDATE_AGE, Duration.ofMinutes(-1)))
            .withMessage("maxNextUpdateAge must be greater than zero");
    }

    @Test
    void whenResponderCertificateLacksSigningExtension_thenThrows() {
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, nonSigningUserCert, true, null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
                DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE))
            .withMessageContaining("Extended Key Usage extension does not contain OCSP Signing, "
                + "which is required for OCSP response signing");
    }

    @Test
    void whenResponderCertificateLacksKeyUsageExtension_thenThrows() {
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(
                FALLBACK_URI, ocspResponder2020Cert, true, null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
                DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE))
            .withMessageContaining("does not contain the Key Usage extension required for OCSP response signing");
    }

    @Test
    void whenResponderCertificateIsNull_thenConstructionSucceeds() {
        assertThatCode(() -> new FallbackOcspServiceConfiguration(
            FALLBACK_URI, null, true, null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
            DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE))
            .doesNotThrowAnyException();
    }

    @Test
    void whenResponderCertificateHasSigningExtension_thenConstructionSucceedsAndAccessorsReturnConfiguredValues() throws Exception {
        FallbackOcspServiceConfiguration nextFallback = new FallbackOcspServiceConfiguration(
            URI.create("http://next.fallback.ocsp.test"), null, false, null,
            ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
            DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE);

        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            FALLBACK_URI, aiaOcspResponderCert, true, nextFallback,
            ISSUER_DN, trustedCaAnchors, trustedCaCertStore,
            Duration.ofMinutes(3), Duration.ofMinutes(4));

        assertThat(configuration.getAccessLocation()).isEqualTo(FALLBACK_URI);
        assertThat(configuration.getResponderCertificate()).isEqualTo(aiaOcspResponderCert);
        assertThat(configuration.doesSupportNonce()).isTrue();
        assertThat(configuration.getNextFallbackConfiguration()).isSameAs(nextFallback);
        assertThat(configuration.getIssuerDN()).isEqualTo(ISSUER_DN);
        assertThat(configuration.getTrustedCACertificateAnchors()).isSameAs(trustedCaAnchors);
        assertThat(configuration.getTrustedCACertificateCertStore()).isSameAs(trustedCaCertStore);
        assertThat(configuration.getMaxThisUpdateAge()).isEqualTo(Duration.ofMinutes(3));
        assertThat(configuration.getMaxNextUpdateAge()).isEqualTo(Duration.ofMinutes(4));
    }
}
