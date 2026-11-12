// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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

import static eu.webeid.ocsp.OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE;
import static eu.webeid.ocsp.OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.TestCertificateBuilder.buildCertificate;
import static org.assertj.core.api.Assertions.assertThatCode;
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
    void whenDesignatedOcspServiceConfigurationResponderCertMissingKeyUsageDigitalSignatureAndNonRepudiation_thenConstructorThrows() throws Exception {
        final X509Certificate responder = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyEncipherment).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> newDesignatedOcspServiceConfiguration(responder))
            .withMessage("Certificate " + responder.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature or Non Repudiation, which is required for OCSP response signing");
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
                " Key Usage extension contains Certificate Signing, which is not allowed for a non-CA OCSP responder certificate");
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
    void whenFallbackOcspServiceConfigurationResponderCertMissingKeyUsageDigitalSignatureAndNonRepudiation_thenConstructorThrows() throws Exception {
        final X509Certificate responder = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyEncipherment).getEncoded()));
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> newFallbackOcspServiceConfiguration(responder))
            .withMessage("Certificate " + responder.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature or Non Repudiation, which is required for OCSP response signing");
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
                " Key Usage extension contains Certificate Signing, which is not allowed for a non-CA OCSP responder certificate");
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

    @Test
    void whenDesignatedOcspServiceConfigurationResponderCertHasKeyUsageNonRepudiation_thenResponderCertIsAccepted() throws Exception {
        final X509Certificate responder = buildResponderCertificateWithKeyUsage(KeyUsage.nonRepudiation);
        assertThatCode(() -> newDesignatedOcspServiceConfiguration(responder))
            .doesNotThrowAnyException();
    }

    @Test
    void whenFallbackOcspServiceConfigurationResponderCertHasKeyUsageNonRepudiation_thenResponderCertIsAccepted() throws Exception {
        final X509Certificate responder = buildResponderCertificateWithKeyUsage(KeyUsage.nonRepudiation);
        final List<X509Certificate> trustedCAs = List.of(getTestEsteid2018CA());
        assertThatCode(() -> new FallbackOcspServiceConfiguration(OCSP_URL, responder, true, null, getTestEsteid2018CA(),
            CertificateValidator.buildTrustAnchorsFromCertificates(trustedCAs),
            CertificateValidator.buildCertStoreFromCertificates(trustedCAs),
            DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE, true))
            .doesNotThrowAnyException();
    }

    @Test
    void whenDesignatedOcspServiceConfigurationKeyUsageNotRequired_thenResponderCertWithoutDigitalSignatureAndNonRepudiationIsRejected() throws Exception {
        final X509Certificate responder = buildResponderCertificateWithKeyUsage(KeyUsage.keyEncipherment);
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> new DesignatedOcspServiceConfiguration(
                OCSP_URL, responder, List.of(getTestEsteid2018CA()), true,
                DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE, false))
            .withMessage("Certificate " + responder.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature or Non Repudiation, which is required for OCSP response signing");
    }

    @Test
    void whenFallbackOcspServiceConfigurationKeyUsageNotRequired_thenResponderCertWithoutDigitalSignatureAndNonRepudiationIsRejected() throws Exception {
        final X509Certificate responder = buildResponderCertificateWithKeyUsage(KeyUsage.keyEncipherment);
        final List<X509Certificate> trustedCAs = List.of(getTestEsteid2018CA());
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() -> new FallbackOcspServiceConfiguration(OCSP_URL, responder, true, null, getTestEsteid2018CA(),
                CertificateValidator.buildTrustAnchorsFromCertificates(trustedCAs),
                CertificateValidator.buildCertStoreFromCertificates(trustedCAs),
                DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE, false))
            .withMessage("Certificate " + responder.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature or Non Repudiation, which is required for OCSP response signing");
    }

    @Test
    void whenDesignatedOcspServiceConfigurationKeyUsageNotRequired_thenResponderCertWithoutKeyUsageIsAccepted() throws Exception {
        final X509Certificate responder = buildResponderCertificateWithoutKeyUsage();
        assertThatCode(() -> new DesignatedOcspServiceConfiguration(
            OCSP_URL, responder, List.of(getTestEsteid2018CA()), true,
            DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE, false))
            .doesNotThrowAnyException();
    }

    @Test
    void whenFallbackOcspServiceConfigurationKeyUsageNotRequired_thenResponderCertWithoutKeyUsageIsAccepted() throws Exception {
        final X509Certificate responder = buildResponderCertificateWithoutKeyUsage();
        final List<X509Certificate> trustedCAs = List.of(getTestEsteid2018CA());
        assertThatCode(() -> new FallbackOcspServiceConfiguration(OCSP_URL, responder, true, null, getTestEsteid2018CA(),
            CertificateValidator.buildTrustAnchorsFromCertificates(trustedCAs),
            CertificateValidator.buildCertStoreFromCertificates(trustedCAs),
            DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE, false))
            .doesNotThrowAnyException();
    }

    private static X509Certificate buildResponderCertificateWithKeyUsage(int keyUsage) throws Exception {
        return buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(keyUsage).getEncoded()),
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning).getEncoded()));
    }

    private static X509Certificate buildResponderCertificateWithoutKeyUsage() throws Exception {
        return buildCertificate(
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning).getEncoded()));
    }

    private static void newDesignatedOcspServiceConfiguration(X509Certificate responder) throws Exception {
        new DesignatedOcspServiceConfiguration(
            OCSP_URL, responder, List.of(getTestEsteid2018CA()), true,
            DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE, true);
    }

    private static void newFallbackOcspServiceConfiguration(X509Certificate responder) throws Exception {
        final List<X509Certificate> trustedCAs = List.of(getTestEsteid2018CA());
        final Set<TrustAnchor> trustAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(trustedCAs);
        final CertStore certStore = CertificateValidator.buildCertStoreFromCertificates(trustedCAs);
        new FallbackOcspServiceConfiguration(OCSP_URL, responder, true, null, null, trustAnchors, certStore,
            DEFAULT_THIS_UPDATE_AGE, DEFAULT_NEXT_UPDATE_AGE, true);
    }

}
