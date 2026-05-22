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
import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotTrustedException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getDemoEsteidSk2018AiaOcspResponder;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2015CA;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.Certificates.getTestSelfSignedOcspResponder;
import static eu.webeid.security.testutil.Certificates.getTestSkOcspResponder2020;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FallbackOcspServiceTest {

    private static final URI PRIMARY_FALLBACK_URI = URI.create("http://primary-fallback.ocsp.test");
    private static final URI SECONDARY_FALLBACK_URI = URI.create("http://secondary-fallback.ocsp.test");
    private static final X500Name ISSUER_DN = new X500Name("CN=TEST of ESTEID-SK 2015, OID.2.5.4.97=NTREE-10747013, O=AS Sertifitseerimiskeskus, C=EE");
    private static final Date VALIDATION_DATE_WITHIN_RESPONDER_VALIDITY = new Date(1630000000000L);

    private static Set<TrustAnchor> trustedCaAnchors;
    private static CertStore trustedCaCertStore;
    private static X509Certificate aiaOcspResponderCert;
    private static X509Certificate selfSignedOcspResponderCert;
    private static X509Certificate ocspResponder2020Cert;
    private static X509Certificate esteid2018CaCert;
    private static X509Certificate nonSigningUserCert;

    @BeforeAll
    static void setUpFixtures() throws Exception {
        List<X509Certificate> trustedCaCertificates = List.of(getTestEsteid2018CA(), getTestEsteid2015CA());
        trustedCaAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(trustedCaCertificates);
        trustedCaCertStore = CertificateValidator.buildCertStoreFromCertificates(trustedCaCertificates);
        // The DEMO AIA responder certificate satisfies the OCSP responder extension requirements
        // (not a CA, Key Usage Digital Signature, no Certificate Signing, Extended Key Usage OCSP Signing)
        // and it chains to the TEST of ESTEID2018 CA, which is one of the trusted CA anchors above.
        aiaOcspResponderCert = getDemoEsteidSk2018AiaOcspResponder();
        // The self-signed responder certificate satisfies the same extension requirements, but no
        // trusted CA issued it. Use it when the PKIX trust check must be the failure.
        selfSignedOcspResponderCert = getTestSelfSignedOcspResponder();
        // TEST of SK OCSP RESPONDER 2020 carries no Key Usage extension at all. Use it only where the
        // Key Usage check must reject the certificate.
        ocspResponder2020Cert = getTestSkOcspResponder2020();
        esteid2018CaCert = getTestEsteid2018CA();
        nonSigningUserCert = getJaakKristjanEsteid2018Cert();
    }

    @Test
    void whenConfigurationIsProvided_thenAccessorsReturnConfiguredValues() throws Exception {
        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            PRIMARY_FALLBACK_URI, aiaOcspResponderCert, true,
            null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);

        FallbackOcspService service = new FallbackOcspService(configuration);

        assertThat(service.getAccessLocation()).isEqualTo(PRIMARY_FALLBACK_URI);
        assertThat(service.doesSupportNonce()).isTrue();
        assertThat(service.getNextFallback()).isNull();
    }

    @Test
    void whenNextFallbackConfigurationProvided_thenChainIsBuiltRecursively() throws Exception {
        FallbackOcspServiceConfiguration secondaryConfiguration = new FallbackOcspServiceConfiguration(
            SECONDARY_FALLBACK_URI, null, false,
            null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);
        FallbackOcspServiceConfiguration primaryConfiguration = new FallbackOcspServiceConfiguration(
            PRIMARY_FALLBACK_URI, null, true,
            secondaryConfiguration, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);

        FallbackOcspService primary = new FallbackOcspService(primaryConfiguration);

        FallbackOcspService secondary = primary.getNextFallback();
        assertThat(secondary).isNotNull();
        assertThat(secondary.getAccessLocation()).isEqualTo(SECONDARY_FALLBACK_URI);
        assertThat(secondary.doesSupportNonce()).isFalse();
        assertThat(secondary.getNextFallback()).isNull();
    }

    @Test
    void whenResponderCertificateIsPinnedAndMatches_thenValidationSucceeds() throws Exception {
        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            PRIMARY_FALLBACK_URI, aiaOcspResponderCert, true,
            null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);
        FallbackOcspService service = new FallbackOcspService(configuration);
        X509CertificateHolder matchingHolder = new X509CertificateHolder(aiaOcspResponderCert.getEncoded());

        assertThatCode(() ->
            service.validateResponderCertificate(matchingHolder, VALIDATION_DATE_WITHIN_RESPONDER_VALIDITY))
            .doesNotThrowAnyException();
    }

    @Test
    void whenResponderCertificateIsPinnedAndDiffers_thenThrows() throws Exception {
        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            PRIMARY_FALLBACK_URI, aiaOcspResponderCert, true,
            null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);
        FallbackOcspService service = new FallbackOcspService(configuration);
        X509CertificateHolder differentHolder = new X509CertificateHolder(esteid2018CaCert.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service.validateResponderCertificate(differentHolder, VALIDATION_DATE_WITHIN_RESPONDER_VALIDITY))
            .withMessage("Responder certificate from the OCSP response is not equal to the configured fallback OCSP responder certificate");
    }

    @Test
    void whenResponderCertificateIsNotPinnedButTrustedByCa_thenValidationSucceeds() throws Exception {
        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            PRIMARY_FALLBACK_URI, null, true,
            null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);
        FallbackOcspService service = new FallbackOcspService(configuration);
        // The DEMO AIA responder certificate chains to the TEST of ESTEID2018 CA, which is a trusted anchor.
        X509CertificateHolder responderHolder = new X509CertificateHolder(aiaOcspResponderCert.getEncoded());

        assertThatCode(() ->
            service.validateResponderCertificate(responderHolder, VALIDATION_DATE_WITHIN_RESPONDER_VALIDITY))
            .doesNotThrowAnyException();
    }

    @Test
    void whenResponderCertificateIsNotPinnedAndLacksSigningExtension_thenThrows() throws Exception {
        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            PRIMARY_FALLBACK_URI, null, true,
            null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);
        FallbackOcspService service = new FallbackOcspService(configuration);
        X509CertificateHolder nonSigningHolder = new X509CertificateHolder(nonSigningUserCert.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service.validateResponderCertificate(nonSigningHolder, VALIDATION_DATE_WITHIN_RESPONDER_VALIDITY))
            .withMessageContaining("Extended Key Usage extension does not contain OCSP Signing, "
                + "which is required for OCSP response signing");
    }

    @Test
    void whenResponderCertificateLacksKeyUsageExtension_thenThrows() throws Exception {
        // TEST of SK OCSP RESPONDER 2020 carries the OCSP-signing EKU, but it has no Key Usage extension.
        // FallbackOcspService runs the certificate extension checks before the PKIX trust check, so the
        // Key Usage check rejects this certificate whatever the configured trust anchors are.
        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            PRIMARY_FALLBACK_URI, null, true,
            null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);
        FallbackOcspService service = new FallbackOcspService(configuration);
        X509CertificateHolder noKeyUsageHolder = new X509CertificateHolder(ocspResponder2020Cert.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service.validateResponderCertificate(noKeyUsageHolder, VALIDATION_DATE_WITHIN_RESPONDER_VALIDITY))
            .withMessageContaining("does not contain the Key Usage extension required for OCSP response signing");
    }

    @Test
    void whenResponderCertificateIsNotPinnedAndNotTrustedByCa_thenThrows() throws Exception {
        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            PRIMARY_FALLBACK_URI, null, true,
            null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);
        FallbackOcspService service = new FallbackOcspService(configuration);
        // The self-signed responder certificate satisfies every OCSP responder extension requirement, but no
        // trusted CA issued it (only the ESTEID2018 and ESTEID-SK 2015 CAs are anchors), so PKIX path building fails.
        X509CertificateHolder untrustedButEkuValidHolder = new X509CertificateHolder(selfSignedOcspResponderCert.getEncoded());

        assertThatExceptionOfType(CertificateNotTrustedException.class)
            .isThrownBy(() ->
                service.validateResponderCertificate(untrustedButEkuValidHolder, VALIDATION_DATE_WITHIN_RESPONDER_VALIDITY));
    }

    @Test
    void whenResponderCertificateHolderConversionFails_thenThrows() throws Exception {
        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            PRIMARY_FALLBACK_URI, aiaOcspResponderCert, true,
            null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);
        FallbackOcspService service = new FallbackOcspService(configuration);
        // Make JcaX509CertificateConverter.getCertificate(holder) fail: the converter calls holder.getEncoded()
        // and wraps the resulting IOException into a CertificateException, which the service catches and rewraps.
        X509CertificateHolder unconvertibleHolder = mock(X509CertificateHolder.class);
        when(unconvertibleHolder.getEncoded()).thenThrow(new IOException("simulated encoding failure"));

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service.validateResponderCertificate(unconvertibleHolder, VALIDATION_DATE_WITHIN_RESPONDER_VALIDITY))
            .withMessageContaining("X509CertificateHolder conversion to X509Certificate failed")
            .withCauseInstanceOf(java.security.cert.CertificateException.class);
    }

    @Test
    void whenResponderCertificateIsExpiredAtValidationDate_thenThrows() throws Exception {
        FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            PRIMARY_FALLBACK_URI, aiaOcspResponderCert, true,
            null, ISSUER_DN, trustedCaAnchors, trustedCaCertStore);
        FallbackOcspService service = new FallbackOcspService(configuration);
        X509CertificateHolder responderHolder = new X509CertificateHolder(aiaOcspResponderCert.getEncoded());
        Date farFuture = new Date(4102444800000L); // 2100-01-01

        assertThatExceptionOfType(CertificateExpiredException.class)
            .isThrownBy(() ->
                service.validateResponderCertificate(responderHolder, farFuture));
    }
}
