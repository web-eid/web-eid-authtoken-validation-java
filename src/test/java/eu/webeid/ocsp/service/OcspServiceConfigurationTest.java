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
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.TestCertificateBuilder.buildCertificate;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class OcspServiceConfigurationTest {

    private static final URI OCSP_URL = URI.create("http://demo.sk.ee/ocsp");

    @Test
    void whenDesignatedOcspServiceConfigurationResponderCertIsCA_thenConstructorThrows() throws Exception {
        final X509Certificate caResponder = buildCertificate(
            new Extension(Extension.basicConstraints, true, new BasicConstraints(0).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> newDesignatedOcspServiceConfiguration(caResponder))
            .withMessage("Certificate " + caResponder.getSubjectX500Principal() +
                " must not be a CA certificate (Basic Constraints CA:TRUE is not allowed for OCSP responder)");
    }

    @Test
    void whenDesignatedOcspServiceConfigurationResponderCertMissingKeyUsageDigitalSignature_thenConstructorThrows() throws Exception {
        final X509Certificate responder = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> newDesignatedOcspServiceConfiguration(responder))
            .withMessage("Certificate " + responder.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature, which is required for OCSP response signing");
    }

    @Test
    void whenDesignatedOcspServiceConfigurationResponderCertHasKeyCertSign_thenConstructorThrows() throws Exception {
        final X509Certificate responder = buildCertificate(
            new Extension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign).getEncoded()),
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> newDesignatedOcspServiceConfiguration(responder))
            .withMessage("Certificate " + responder.getSubjectX500Principal() +
                " Key Usage extension contains Certificate Signing, which is not allowed for OCSP responder");
    }

    @Test
    void whenDesignatedOcspServiceConfigurationResponderCertMissingOcspSigningEku_thenConstructorThrows() throws Exception {
        final X509Certificate responder = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).getEncoded()),
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> newDesignatedOcspServiceConfiguration(responder))
            .withMessage("Certificate " + responder.getSubjectX500Principal() +
                " Extended Key Usage extension does not contain OCSP Signing, which is required for OCSP response signing");
    }

    @Test
    void whenFallbackOcspServiceConfigurationResponderCertIsCA_thenConstructorThrows() throws Exception {
        final X509Certificate caResponder = buildCertificate(
            new Extension(Extension.basicConstraints, true, new BasicConstraints(0).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> newFallbackOcspServiceConfiguration(caResponder))
            .withMessage("Certificate " + caResponder.getSubjectX500Principal() +
                " must not be a CA certificate (Basic Constraints CA:TRUE is not allowed for OCSP responder)");
    }

    @Test
    void whenFallbackOcspServiceConfigurationResponderCertMissingKeyUsageDigitalSignature_thenConstructorThrows() throws Exception {
        final X509Certificate responder = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> newFallbackOcspServiceConfiguration(responder))
            .withMessage("Certificate " + responder.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature, which is required for OCSP response signing");
    }

    @Test
    void whenFallbackOcspServiceConfigurationResponderCertHasKeyCertSign_thenConstructorThrows() throws Exception {
        final X509Certificate responder = buildCertificate(
            new Extension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign).getEncoded()),
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> newFallbackOcspServiceConfiguration(responder))
            .withMessage("Certificate " + responder.getSubjectX500Principal() +
                " Key Usage extension contains Certificate Signing, which is not allowed for OCSP responder");
    }

    @Test
    void whenFallbackOcspServiceConfigurationResponderCertMissingOcspSigningEku_thenConstructorThrows() throws Exception {
        final X509Certificate responder = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).getEncoded()),
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> newFallbackOcspServiceConfiguration(responder))
            .withMessage("Certificate " + responder.getSubjectX500Principal() +
                " Extended Key Usage extension does not contain OCSP Signing, which is required for OCSP response signing");
    }

    private static void newDesignatedOcspServiceConfiguration(X509Certificate responder) throws Exception {
        new DesignatedOcspServiceConfiguration(
            OCSP_URL, responder, List.of(getTestEsteid2018CA()), true);
    }

    private static void newFallbackOcspServiceConfiguration(X509Certificate responder) throws Exception {
        final List<X509Certificate> trustedCAs = List.of(getTestEsteid2018CA());
        final Set<TrustAnchor> trustAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(trustedCAs);
        final CertStore certStore = CertificateValidator.buildCertStoreFromCertificates(trustedCAs);
        new FallbackOcspServiceConfiguration(OCSP_URL, responder, true, null, null, trustAnchors, certStore);
    }

}
