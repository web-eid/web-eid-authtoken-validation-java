// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.CertificateNotTrustedException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static eu.webeid.ocsp.service.OcspServiceMaker.getAiaOcspServiceProvider;
import static eu.webeid.ocsp.service.OcspServiceMaker.getDesignatedOcspServiceProvider;
import static eu.webeid.security.testutil.Certificates.getDemoEsteidSk2018AiaOcspResponder;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.Certificates.getTestSelfSignedOcspResponder;
import static eu.webeid.security.testutil.TestCertificateBuilder.buildCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class OcspServiceProviderTest {

    @Test
    void whenDesignatedOcspServiceConfigurationProvided_thenCreatesDesignatedOcspService() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getDesignatedOcspServiceProvider();
        final OcspService service = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert());
        assertThat(service.getAccessLocation()).isEqualTo(new URI("http://demo.sk.ee/ocsp"));
        assertThat(service.doesSupportNonce()).isTrue();
        assertThatCode(() ->
            service.validateResponderCertificate(new X509CertificateHolder(getTestSelfSignedOcspResponder().getEncoded()), new Date(1630000000000L)))
            .doesNotThrowAnyException();
        assertThatCode(() ->
            service.validateResponderCertificate(new X509CertificateHolder(getTestEsteid2018CA().getEncoded()), new Date(1630000000000L)))
            .isInstanceOf(OCSPCertificateException.class)
            .hasMessage("Responder certificate from the OCSP response is not equal to the configured designated OCSP responder certificate");
    }

    @Test
    void whenAiaOcspServiceConfigurationProvided_thenCreatesAiaOcspService() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert());
        assertThat(service2018.getAccessLocation()).isEqualTo(new URI("http://aia.demo.sk.ee/esteid2018"));
        assertThat(service2018.doesSupportNonce()).isTrue();
        assertThatCode(() ->
            service2018.validateResponderCertificate(new X509CertificateHolder(getDemoEsteidSk2018AiaOcspResponder().getEncoded()), new Date(1630000000000L)))
            .doesNotThrowAnyException();
    }

    @Test
    void whenAiaOcspServiceConfigurationDoesNotHaveResponderCertTrustedCA_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert());
        final X509Certificate untrustedResponder = getTestSelfSignedOcspResponder();
        final X509CertificateHolder untrustedResponderCert = new X509CertificateHolder(untrustedResponder.getEncoded());
        assertThatExceptionOfType(CertificateNotTrustedException.class)
            .isThrownBy(() ->
                service2018.validateResponderCertificate(untrustedResponderCert, new Date(1630000000000L)))
            .withMessage("Certificate " + untrustedResponder.getSubjectX500Principal() + " is not trusted");
    }

    @Test
    void whenAiaOcspResponderCertIsCA_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert());
        final X509Certificate caResponder = buildCertificate(
            new Extension(Extension.basicConstraints, true, new BasicConstraints(0).getEncoded()));
        final X509CertificateHolder caResponderCert = new X509CertificateHolder(caResponder.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service2018.validateResponderCertificate(caResponderCert, new Date()))
            .withMessage("Certificate " + caResponder.getSubjectX500Principal() +
                " must not be a CA certificate (Basic Constraints CA:TRUE is not allowed for OCSP responder)");
    }

    @Test
    void whenAiaOcspResponderCertMissingKeyUsageDigitalSignature_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert());
        final X509Certificate responderWithoutDigitalSignature = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation).getEncoded()));
        final X509CertificateHolder responderCert = new X509CertificateHolder(responderWithoutDigitalSignature.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service2018.validateResponderCertificate(responderCert, new Date()))
            .withMessage("Certificate " + responderWithoutDigitalSignature.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature, which is required for OCSP response signing");
    }

    @Test
    void whenAiaOcspResponderCertMissingOcspSigningEku_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert());
        final X509Certificate responderWithoutOcspSigning = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).getEncoded()),
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth).getEncoded()));
        final X509CertificateHolder responderCert = new X509CertificateHolder(responderWithoutOcspSigning.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service2018.validateResponderCertificate(responderCert, new Date()))
            .withMessage("Certificate " + responderWithoutOcspSigning.getSubjectX500Principal() +
                " Extended Key Usage extension does not contain OCSP Signing, which is required for OCSP response signing");
    }

    @Test
    void whenFallbackOcspResponderCertIsCA_thenThrows() throws Exception {
        final FallbackOcspService service = newFallbackOcspServiceWithoutPinnedResponder();
        final X509Certificate caResponder = buildCertificate(
            new Extension(Extension.basicConstraints, true, new BasicConstraints(0).getEncoded()));
        final X509CertificateHolder caResponderCert = new X509CertificateHolder(caResponder.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service.validateResponderCertificate(caResponderCert, new Date()))
            .withMessage("Certificate " + caResponder.getSubjectX500Principal() +
                " must not be a CA certificate (Basic Constraints CA:TRUE is not allowed for OCSP responder)");
    }

    @Test
    void whenFallbackOcspResponderCertMissingKeyUsageDigitalSignature_thenThrows() throws Exception {
        final FallbackOcspService service = newFallbackOcspServiceWithoutPinnedResponder();
        final X509Certificate responderWithoutDigitalSignature = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation).getEncoded()));
        final X509CertificateHolder responderCert = new X509CertificateHolder(responderWithoutDigitalSignature.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service.validateResponderCertificate(responderCert, new Date()))
            .withMessage("Certificate " + responderWithoutDigitalSignature.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature, which is required for OCSP response signing");
    }

    @Test
    void whenFallbackOcspResponderCertMissingOcspSigningEku_thenThrows() throws Exception {
        final FallbackOcspService service = newFallbackOcspServiceWithoutPinnedResponder();
        final X509Certificate responderWithoutOcspSigning = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).getEncoded()),
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth).getEncoded()));
        final X509CertificateHolder responderCert = new X509CertificateHolder(responderWithoutOcspSigning.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service.validateResponderCertificate(responderCert, new Date()))
            .withMessage("Certificate " + responderWithoutOcspSigning.getSubjectX500Principal() +
                " Extended Key Usage extension does not contain OCSP Signing, which is required for OCSP response signing");
    }

    private static FallbackOcspService newFallbackOcspServiceWithoutPinnedResponder() throws Exception {
        final List<X509Certificate> trustedCAs = List.of(getTestEsteid2018CA());
        final Set<TrustAnchor> trustAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(trustedCAs);
        final CertStore certStore = CertificateValidator.buildCertStoreFromCertificates(trustedCAs);
        final FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            URI.create("http://fallback.demo.sk.ee/ocsp"), null, true, null, new X500Name("CN=TEST ISSUER"), trustAnchors, certStore);
        return new FallbackOcspService(configuration);
    }

}

// Old disabled example AuthTokenValidator test with designated OCSP check.
//
//    @Test
//    @Disabled("A new designated test OCSP responder certificate was issued whose validity period no longer overlaps with the revoked certificate")
//    void whenCertificateIsRevoked_thenOcspCheckWithDesignatedOcspServiceFails() throws Exception {
//        mockDate("2020-01-01", mockedClock);
//        final AuthTokenValidator validatorWithOcspCheck = AuthTokenValidators.getAuthTokenValidatorWithDesignatedOcspCheck();
//        final WebEidAuthToken token = replaceTokenField(AUTH_TOKEN, "X5C", REVOKED_CERT);
//        assertThatThrownBy(() -> validatorWithOcspCheck
//            .validate(token, VALID_CHALLENGE_NONCE))
//            .isInstanceOf(UserCertificateRevokedException.class);
//    }
