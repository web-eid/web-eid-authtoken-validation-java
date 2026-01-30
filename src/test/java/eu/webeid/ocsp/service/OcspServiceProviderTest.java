// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.service;

import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.testutil.LocalOcspResponder;

import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static eu.webeid.ocsp.service.OcspServiceMaker.getAiaOcspServiceProvider;
import static eu.webeid.ocsp.service.OcspServiceMaker.getDesignatedOcspServiceProvider;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getMariliisEsteid2015Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2015CA;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.Certificates.getTestSkOcspResponder2020;
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
        assertThatCode(() ->
            service.validateResponderCertificate(new X509CertificateHolder(getTestSkOcspResponder2020().getEncoded()), getTestEsteid2018CA(), new Date(1630000000000L)))
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
    }

    @Test
    void whenAiaResponderCertificateLacksOcspSigningUsage_thenThrows() throws Exception {
        final OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        final OcspService service2018 = ocspServiceProvider.getService(getJaakKristjanEsteid2018Cert(), getTestEsteid2018CA());
        final X509CertificateHolder wrongResponderCert = new X509CertificateHolder(getMariliisEsteid2015Cert().getEncoded());
        assertThatExceptionOfType(OCSPCertificateException.class)
            .isThrownBy(() ->
                service2018.validateResponderCertificate(wrongResponderCert, getTestEsteid2018CA(), new Date(1630000000000L)))
            .withMessageContaining("does not contain the key usage extension for OCSP response signing");
    }

    @Test
    void whenDifferentIssuersHaveSameName_thenDesignatedServiceAppliesOnlyToConfiguredCertificate() throws Exception {
        try (LocalOcspResponder first = new LocalOcspResponder();
             LocalOcspResponder second = new LocalOcspResponder()) {
            first.start();
            second.start();
            final var authorities = List.of(first.issuer(), second.issuer());
            final var designated = new DesignatedOcspServiceConfiguration(
                    first.designatedUri(), first.responderCertificate(), List.of(first.issuer()), true);
            final var aia = new AiaOcspServiceConfiguration(Set.of(),
                    CertificateValidator.buildTrustAnchorsFromCertificates(authorities),
                    CertificateValidator.buildCertStoreFromCertificates(authorities));
            final var provider = new OcspServiceProvider(designated, aia);

            assertThat(first.issuer().getSubjectX500Principal()).isEqualTo(second.issuer().getSubjectX500Principal());
            assertThat(first.issuer()).isNotEqualTo(second.issuer());
            assertThat(provider.getService(first.subject(), first.issuer())).isInstanceOf(DesignatedOcspService.class);
            assertThat(provider.getService(second.subject(), second.issuer())).isInstanceOf(AiaOcspService.class);
        }
    }

    @Test
    void whenDifferentIssuersHaveSameName_thenFallbackServiceAppliesOnlyToConfiguredCertificate() throws Exception {
        try (LocalOcspResponder first = new LocalOcspResponder();
             LocalOcspResponder second = new LocalOcspResponder()) {
            first.start();
            second.start();
            final var authorities = List.of(first.issuer(), second.issuer());
            final var aia = new AiaOcspServiceConfiguration(Set.of(),
                    CertificateValidator.buildTrustAnchorsFromCertificates(authorities),
                    CertificateValidator.buildCertStoreFromCertificates(authorities));
            final var fallback = new FallbackOcspServiceConfiguration(
                    first.designatedUri(),
                    first.responderCertificate(),
                    true,
                    null,
                    first.issuer(),
                    CertificateValidator.buildTrustAnchorsFromCertificates(List.of(first.issuer())),
                    CertificateValidator.buildCertStoreFromCertificates(List.of(first.issuer())));
            final var provider = new OcspServiceProvider(null, aia, List.of(fallback));

            assertThat(first.issuer().getSubjectX500Principal()).isEqualTo(second.issuer().getSubjectX500Principal());
            assertThat(first.issuer()).isNotEqualTo(second.issuer());
            assertThat(provider.getService(first.subject(), first.issuer()).getFallbackService()).isPresent();
            assertThat(provider.getService(second.subject(), second.issuer()).getFallbackService()).isEmpty();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void whenFallbackResponderIsDelegatedByAnotherTrustedCa_thenThrows(boolean sameIssuerName) throws Exception {
        try (LocalOcspResponder responder = new LocalOcspResponder()) {
            responder.start();
            responder.replaceResponderCertificateFromDifferentIssuer(sameIssuerName);
            final var configuration = new FallbackOcspServiceConfiguration(
                    responder.designatedUri(),
                    null,
                    true,
                    null,
                    responder.issuer(),
                    CertificateValidator.buildTrustAnchorsFromCertificates(List.of(responder.issuer(), responder.otherIssuer())),
                    CertificateValidator.buildCertStoreFromCertificates(List.of(responder.issuer(), responder.otherIssuer())));
            final var service = new FallbackOcspService(configuration);
            final var responderCertificate = new X509CertificateHolder(responder.responderCertificate().getEncoded());

            assertThatExceptionOfType(OCSPCertificateException.class)
                    .isThrownBy(() -> service.validateResponderCertificate(
                            responderCertificate, responder.issuer(), Date.from(responder.now())));
        }
    }

    @Test
    void whenFallbackServiceIsUsedForDifferentIssuer_thenThrows() throws Exception {
        try (LocalOcspResponder first = new LocalOcspResponder();
             LocalOcspResponder second = new LocalOcspResponder()) {
            first.start();
            second.start();
            final var configuration = new FallbackOcspServiceConfiguration(
                    first.designatedUri(),
                    first.responderCertificate(),
                    true,
                    null,
                    first.issuer(),
                    CertificateValidator.buildTrustAnchorsFromCertificates(List.of(first.issuer())),
                    CertificateValidator.buildCertStoreFromCertificates(List.of(first.issuer())));
            final var service = new FallbackOcspService(configuration);
            final var responderCertificate = new X509CertificateHolder(first.responderCertificate().getEncoded());

            assertThatExceptionOfType(OCSPCertificateException.class)
                    .isThrownBy(() -> service.validateResponderCertificate(
                            responderCertificate, second.issuer(), Date.from(first.now())))
                    .withMessage("Fallback OCSP service is not configured for the subject certificate's issuer");
        }
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
