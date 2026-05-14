// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import eu.webeid.ocsp.OcspCertificateRevocationChecker;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.security.certificate.CertificateValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;
import eu.webeid.security.testutil.LocalOcspResponder;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static eu.webeid.ocsp.service.OcspServiceMaker.getAiaOcspServiceProvider;
import static eu.webeid.ocsp.service.OcspServiceMaker.getDesignatedOcspServiceConfiguration;
import static eu.webeid.ocsp.service.OcspServiceMaker.getDesignatedOcspServiceProvider;
import static eu.webeid.security.testutil.Certificates.getDemoEsteidSk2018AiaOcspResponder;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2015CA;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.Certificates.getMariliisEsteid2015Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2015CA;
import static eu.webeid.security.testutil.Certificates.getTestSelfSignedOcspResponder;
import static eu.webeid.security.testutil.TestCertificateBuilder.buildCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class OcspServiceProviderTest {

    @Test
    void whenDesignatedOcspServiceConfigurationProvided_thenCreatesDesignatedOcspService() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getDesignatedOcspServiceProvider();
        final OcspService service = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert(), getTestEsteid2018CA());
        assertThat(service.getAccessLocation()).isEqualTo(new URI("http://demo.sk.ee/ocsp"));
        assertThat(service.doesSupportNonce()).isTrue();
        assertThat(service.getMaxThisUpdateAge()).isEqualTo(Duration.ofMinutes(3));
        assertThat(service.getMaxNextUpdateAge()).isEqualTo(Duration.ofMinutes(20));
        assertThatCode(() ->
            service.validateResponderCertificate(new X509CertificateHolder(getTestSelfSignedOcspResponder().getEncoded()), getTestEsteid2018CA(), new Date(1630000000000L)))
            .doesNotThrowAnyException();
        assertThatCode(() ->
            service.validateResponderCertificate(new X509CertificateHolder(getTestEsteid2018CA().getEncoded()), getTestEsteid2018CA(), new Date(1630000000000L)))
            .isInstanceOf(OCSPCertificateException.class)
            .hasMessage("Responder certificate from the OCSP response is not equal to the configured designated OCSP responder certificate");
    }

    @Test
    void whenAiaOcspServiceConfigurationProvided_thenCreatesAiaOcspService() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert(), getTestEsteid2018CA());
        assertThat(service2018.getAccessLocation()).isEqualTo(new URI("http://aia.demo.sk.ee/esteid2018"));
        assertThat(service2018.doesSupportNonce()).isTrue();

        final OcspService service2015 = ocspServiceProvider.getService(getMariliisEsteid2015Cert(), getTestEsteid2015CA());
        assertThat(service2015.getAccessLocation()).isEqualTo(new URI("http://aia.demo.sk.ee/esteid2015"));
        assertThat(service2015.doesSupportNonce()).isFalse();
        assertThat(service2018.getMaxThisUpdateAge()).isEqualTo(Duration.ofMinutes(3));
        assertThat(service2018.getMaxNextUpdateAge()).isEqualTo(Duration.ofMinutes(20));
        assertThatCode(() ->
            service2018.validateResponderCertificate(new X509CertificateHolder(getDemoEsteidSk2018AiaOcspResponder().getEncoded()), getTestEsteid2018CA(), new Date(1630000000000L)))
            .doesNotThrowAnyException();
    }

    @Test
    void whenAiaResponderCertificateLacksOcspSigningUsage_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert(), getTestEsteid2018CA());
        final X509CertificateHolder wrongResponderCert = new X509CertificateHolder(getMariliisEsteid2015Cert().getEncoded());
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service2018.validateResponderCertificate(wrongResponderCert, getTestEsteid2018CA(), new Date(1630000000000L)))
            .withMessageContaining("Key Usage extension does not contain Digital Signature, which is required for OCSP response signing");
    }

    @Test
    void whenDifferentIssuersHaveSameName_thenDesignatedServiceAppliesOnlyToConfiguredCertificate() throws Exception {
        try (LocalOcspResponder first = new LocalOcspResponder();
             LocalOcspResponder second = new LocalOcspResponder()) {
            first.start();
            second.start();
            final var authorities = List.of(first.issuer(), second.issuer());
            final var designated = new DesignatedOcspServiceConfiguration(
                    first.designatedUri(), first.responderCertificate(), List.of(first.issuer()), true,
                    OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE, OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE);
            final var aia = new AiaOcspServiceConfiguration(Set.of(),
                    CertificateValidator.buildTrustAnchorsFromCertificates(authorities),
                    CertificateValidator.buildCertStoreFromCertificates(authorities),
                    OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE, OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE);
            final var provider = new OcspServiceProvider(designated, aia);

            assertThat(first.issuer().getSubjectX500Principal()).isEqualTo(second.issuer().getSubjectX500Principal());
            assertThat(first.issuer()).isNotEqualTo(second.issuer());
            assertThat(provider.getService(first.subject(), first.issuer())).isInstanceOf(DesignatedOcspService.class);
            assertThat(provider.getService(second.subject(), second.issuer())).isInstanceOf(AiaOcspService.class);
        }
    }

    @Test
    void whenAiaOcspResponderCertIsCA_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert(), getTestEsteid2018CA());
        final X509Certificate caResponder = buildCertificate(
            new Extension(Extension.basicConstraints, true, new BasicConstraints(0).getEncoded()));
        final X509CertificateHolder caResponderCert = new X509CertificateHolder(caResponder.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service2018.validateResponderCertificate(caResponderCert, getTestEsteid2018CA(), new Date()))
            .withMessage("Certificate " + caResponder.getSubjectX500Principal() +
                " must not be a CA certificate (Basic Constraints CA:TRUE is not allowed for OCSP responder)");
    }

    @Test
    void whenAiaOcspResponderCertMissingKeyUsageDigitalSignature_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert(), getTestEsteid2018CA());
        final X509Certificate responderWithoutDigitalSignature = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation).getEncoded()));
        final X509CertificateHolder responderCert = new X509CertificateHolder(responderWithoutDigitalSignature.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service2018.validateResponderCertificate(responderCert, getTestEsteid2018CA(), new Date()))
            .withMessage("Certificate " + responderWithoutDigitalSignature.getSubjectX500Principal() +
                " Key Usage extension does not contain Digital Signature, which is required for OCSP response signing");
    }

    @Test
    void whenAiaOcspResponderCertMissingOcspSigningEku_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert(), getTestEsteid2018CA());
        final X509Certificate responderWithoutOcspSigning = buildCertificate(
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).getEncoded()),
            new Extension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth).getEncoded()));
        final X509CertificateHolder responderCert = new X509CertificateHolder(responderWithoutOcspSigning.getEncoded());

        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service2018.validateResponderCertificate(responderCert, getTestEsteid2018CA(), new Date()))
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
                service.validateResponderCertificate(caResponderCert, getTestEsteid2018CA(), new Date()))
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
                service.validateResponderCertificate(responderCert, getTestEsteid2018CA(), new Date()))
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
                service.validateResponderCertificate(responderCert, getTestEsteid2018CA(), new Date()))
            .withMessage("Certificate " + responderWithoutOcspSigning.getSubjectX500Principal() +
                " Extended Key Usage extension does not contain OCSP Signing, which is required for OCSP response signing");
    }

    private static FallbackOcspService newFallbackOcspServiceWithoutPinnedResponder() throws Exception {
        final List<X509Certificate> trustedCAs = List.of(getTestEsteid2018CA());
        final Set<TrustAnchor> trustAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(trustedCAs);
        final CertStore certStore = CertificateValidator.buildCertStoreFromCertificates(trustedCAs);
        final FallbackOcspServiceConfiguration configuration = new FallbackOcspServiceConfiguration(
            URI.create("http://fallback.demo.sk.ee/ocsp"), null, true, null, new X500Name("CN=TEST ISSUER"), trustAnchors, certStore,
            OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE,
            OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE);
        return new FallbackOcspService(configuration);
    }

    @Test
    void whenFallbackOcspServiceConfigurationProvided_thenAiaServiceCarriesMatchingFallback() throws Exception {
        X509Certificate userCert = getJaakKristjanEsteid2018Cert();
        X500Name issuerDN = X500Name.getInstance(getTestEsteid2018CA().getSubjectX500Principal().getEncoded());
        List<X509Certificate> trustedCertificates = List.of(getTestEsteid2018CA(), getTestEsteid2015CA());
        Set<java.security.cert.TrustAnchor> trustedAnchors =
            CertificateValidator.buildTrustAnchorsFromCertificates(trustedCertificates);
        java.security.cert.CertStore trustedStore =
            CertificateValidator.buildCertStoreFromCertificates(trustedCertificates);
        URI fallbackUri = URI.create("http://fallback.test/ocsp");
        FallbackOcspServiceConfiguration fallbackConfiguration = new FallbackOcspServiceConfiguration(
            fallbackUri, getDemoEsteidSk2018AiaOcspResponder(), true,
            null, issuerDN, trustedAnchors, trustedStore,
            OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE,
            OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE);

        OcspServiceProvider provider = new OcspServiceProvider(null, getAiaOcspServiceProvider2018Configuration(),
            List.of(fallbackConfiguration));
        OcspService service = provider.getService(userCert, getTestEsteid2018CA());

        assertThat(service).isInstanceOf(AiaOcspService.class);
        Optional<FallbackOcspService> fallbackOpt = service.getFallbackService();
        assertThat(fallbackOpt).isPresent();
        FallbackOcspService fallback = fallbackOpt.get();
        assertThat(fallback.getAccessLocation()).isEqualTo(fallbackUri);
        assertThat(fallback.doesSupportNonce()).isTrue();
        Date validationDate = new Date(1630000000000L);
        assertThatCode(() ->
            fallback.validateResponderCertificate(new X509CertificateHolder(getDemoEsteidSk2018AiaOcspResponder().getEncoded()), getTestEsteid2018CA(), validationDate))
            .doesNotThrowAnyException();
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                fallback.validateResponderCertificate(new X509CertificateHolder(getTestEsteid2018CA().getEncoded()), getTestEsteid2018CA(), validationDate))
            .withMessage("Responder certificate from the OCSP response is not equal to the configured fallback OCSP responder certificate");
    }

    @Test
    void whenFallbackOcspServiceConfigurationDoesNotMatchIssuer_thenAiaServiceCarriesNoFallback() throws Exception {
        X509Certificate userCert = getJaakKristjanEsteid2018Cert();
        List<X509Certificate> trustedCertificates = List.of(getTestEsteid2018CA(), getTestEsteid2015CA());
        Set<java.security.cert.TrustAnchor> trustedAnchors =
            CertificateValidator.buildTrustAnchorsFromCertificates(trustedCertificates);
        java.security.cert.CertStore trustedStore =
            CertificateValidator.buildCertStoreFromCertificates(trustedCertificates);
        X500Name unrelatedIssuerDN = new X500Name("CN=Unrelated CA");
        FallbackOcspServiceConfiguration fallbackConfiguration = new FallbackOcspServiceConfiguration(
            URI.create("http://fallback.test/ocsp"), null, true,
            null, unrelatedIssuerDN, trustedAnchors, trustedStore,
            OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE,
            OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE);

        OcspServiceProvider provider = new OcspServiceProvider(null, getAiaOcspServiceProvider2018Configuration(),
            List.of(fallbackConfiguration));
        OcspService service = provider.getService(userCert, getTestEsteid2018CA());

        assertThat(service.getFallbackService()).isEmpty();
    }

    @Test
    void whenFallbackConfigurationsIsNull_thenServiceHasNoFallback() throws Exception {
        X509Certificate userCert = getJaakKristjanEsteid2018Cert();
        OcspServiceProvider provider = new OcspServiceProvider(null, getAiaOcspServiceProvider2018Configuration(), null);

        OcspService service = provider.getService(userCert, getTestEsteid2018CA());

        assertThat(service).isInstanceOf(AiaOcspService.class);
        assertThat(service.getAccessLocation()).isEqualTo(new URI("http://aia.demo.sk.ee/esteid2018"));
        assertThat(service.getFallbackService()).isEmpty();
    }

    @Test
    void whenFallbackConfigurationsIsEmpty_thenServiceHasNoFallback() throws Exception {
        X509Certificate userCert = getJaakKristjanEsteid2018Cert();
        OcspServiceProvider provider = new OcspServiceProvider(null, getAiaOcspServiceProvider2018Configuration(), List.of());

        OcspService service = provider.getService(userCert, getTestEsteid2018CA());

        assertThat(service).isInstanceOf(AiaOcspService.class);
        assertThat(service.getFallbackService()).isEmpty();
    }

    @Test
    void whenDesignatedServiceSupportsIssuer_thenDesignatedTakesPrecedenceOverFallback() throws Exception {
        X509Certificate userCert = getJaakKristjanEsteid2018Cert();
        X500Name issuerDN = X500Name.getInstance(getTestEsteid2018CA().getSubjectX500Principal().getEncoded());
        List<X509Certificate> trustedCertificates = List.of(getTestEsteid2018CA(), getTestEsteid2015CA());
        Set<java.security.cert.TrustAnchor> trustedAnchors =
            CertificateValidator.buildTrustAnchorsFromCertificates(trustedCertificates);
        java.security.cert.CertStore trustedStore =
            CertificateValidator.buildCertStoreFromCertificates(trustedCertificates);
        FallbackOcspServiceConfiguration fallbackConfiguration = new FallbackOcspServiceConfiguration(
            URI.create("http://fallback.test/ocsp"), getDemoEsteidSk2018AiaOcspResponder(), true,
            null, issuerDN, trustedAnchors, trustedStore,
            OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE,
            OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE);

        OcspServiceProvider provider = new OcspServiceProvider(getDesignatedOcspServiceConfiguration(),
            getAiaOcspServiceProvider2018Configuration(), List.of(fallbackConfiguration));
        OcspService service = provider.getService(userCert, getTestEsteid2018CA());

        assertThat(service).isInstanceOf(DesignatedOcspService.class);
        assertThat(service.getAccessLocation()).isEqualTo(new URI("http://demo.sk.ee/ocsp"));
        assertThat(service.getFallbackService()).isEmpty();
    }

    @Test
    void whenDuplicateIssuerFallbackConfigurations_thenLastOneWins() throws Exception {
        X509Certificate userCert = getJaakKristjanEsteid2018Cert();
        X500Name issuerDN = X500Name.getInstance(getTestEsteid2018CA().getSubjectX500Principal().getEncoded());
        List<X509Certificate> trustedCertificates = List.of(getTestEsteid2018CA(), getTestEsteid2015CA());
        Set<java.security.cert.TrustAnchor> trustedAnchors =
            CertificateValidator.buildTrustAnchorsFromCertificates(trustedCertificates);
        java.security.cert.CertStore trustedStore =
            CertificateValidator.buildCertStoreFromCertificates(trustedCertificates);
        URI firstFallbackUri = URI.create("http://fallback-first.test/ocsp");
        URI lastFallbackUri = URI.create("http://fallback-last.test/ocsp");
        FallbackOcspServiceConfiguration firstConfiguration = new FallbackOcspServiceConfiguration(
            firstFallbackUri, getDemoEsteidSk2018AiaOcspResponder(), true,
            null, issuerDN, trustedAnchors, trustedStore,
            OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE,
            OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE);
        FallbackOcspServiceConfiguration lastConfiguration = new FallbackOcspServiceConfiguration(
            lastFallbackUri, getDemoEsteidSk2018AiaOcspResponder(), true,
            null, issuerDN, trustedAnchors, trustedStore,
            OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE,
            OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE);

        OcspServiceProvider provider = new OcspServiceProvider(null, getAiaOcspServiceProvider2018Configuration(),
            List.of(firstConfiguration, lastConfiguration));
        OcspService service = provider.getService(userCert, getTestEsteid2018CA());

        Optional<FallbackOcspService> fallbackOpt = service.getFallbackService();
        assertThat(fallbackOpt).isPresent();
        assertThat(fallbackOpt.get().getAccessLocation()).isEqualTo(lastFallbackUri);
    }

    private static AiaOcspServiceConfiguration getAiaOcspServiceProvider2018Configuration() throws Exception {
        List<X509Certificate> trustedCertificates = List.of(getTestEsteid2018CA(), getTestEsteid2015CA());
        return new AiaOcspServiceConfiguration(
            Set.of(),
            CertificateValidator.buildTrustAnchorsFromCertificates(trustedCertificates),
            CertificateValidator.buildCertStoreFromCertificates(trustedCertificates),
            OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE,
            OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE);
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
