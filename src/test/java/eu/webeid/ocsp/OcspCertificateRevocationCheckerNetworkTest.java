// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp;

import eu.webeid.ocsp.client.OcspClientImpl;
import eu.webeid.ocsp.exceptions.OCSPCertificateException;
import eu.webeid.ocsp.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.ocsp.service.AiaOcspServiceConfiguration;
import eu.webeid.ocsp.service.DesignatedOcspServiceConfiguration;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.CertificateRevocationCheckFailedException;
import eu.webeid.security.exceptions.CertificateRevokedException;
import eu.webeid.security.testutil.LocalOcspResponder;
import eu.webeid.security.testutil.LocalOcspResponder.Reply;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Exercises the bundled OCSP checker against a local, signing responder. */
class OcspCertificateRevocationCheckerNetworkTest {

    private LocalOcspResponder responder;

    @BeforeEach
    void startResponder() throws Exception {
        responder = new LocalOcspResponder();
        responder.start();
    }

    @AfterEach
    void stopResponder() {
        if (responder != null) {
            responder.close();
        }
    }

    @Test
    void whenResponderReturnsGood_thenValidationSendsRequestAndSucceeds() throws Exception {
        final List<RevocationInfo> info = validate();

        assertRequestReachedResponder();
        assertThat(responder.requestNonce()).hasSize(32);
        assertThat(info).singleElement().extracting(RevocationInfo::ocspResponderUri).isEqualTo(responder.designatedUri());
    }

    @Test
    void whenResponderReturnsRevoked_thenValidationRejectsCertificate() {
        responder.setReply(Reply.REVOKED);

        assertThatThrownBy(this::validate).isInstanceOf(CertificateRevokedException.class);
        assertRequestReachedResponder();
    }

    @Test
    void whenResponderReturnsTryLater_thenValidationReportsFailure() {
        responder.setReply(Reply.TRY_LATER);

        assertThatThrownBy(this::validate).isInstanceOf(CertificateRevocationCheckFailedException.class);
        assertRequestReachedResponder();
    }

    @Test
    void whenResponderDisconnects_thenValidationReportsFailureWithCause() {
        responder.setReply(Reply.DISCONNECT);

        assertThatThrownBy(this::validate)
                .isInstanceOf(CertificateRevocationCheckFailedException.class)
                .hasRootCauseInstanceOf(IOException.class);
        assertRequestReachedResponder();
    }

    @ParameterizedTest
    @EnumSource(value = Reply.class, names = {"UNSUPPORTED_TYPE", "MISSING_RESPONSE"})
    void whenBasicResponseIsMissingOrUnsupported_thenCustomCheckerReportsFailure(Reply response) {
        responder.setReply(response);

        assertThatThrownBy(this::validate)
                .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
                .hasMessageContaining("Missing or unsupported Basic OCSP Response");
        assertRequestReachedResponder();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void whenDesignatedResponderOmitsNonce_thenConfiguredPolicyIsEnforced(boolean nonceEnabled) throws Exception {
        responder.setIncludeNonce(false);

        if (nonceEnabled) {
            assertThatThrownBy(this::validate)
                    .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
                    .hasMessageContaining("nonce extension missing");
        } else {
            validate(false);
            assertThat(responder.requestNonce()).isNull();
        }
        assertRequestReachedResponder();
    }

    @Test
    void whenDesignatedResponderCertificateDiffers_thenFailurePreservesCertificateCause() throws Exception {
        final var checker = customChecker(new DesignatedOcspServiceConfiguration(
                responder.designatedUri(), responder.responderCertificate(), List.of(responder.issuer()), true,
                OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE, OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE));
        responder.replaceResponderCertificate(true);

        assertThatThrownBy(() -> checker.validateCertificateNotRevoked(responder.subject(), responder.issuer()))
                .isInstanceOf(CertificateRevocationCheckFailedException.class)
                .hasMessageContaining(responder.designatedUri().toString())
                .cause()
                .isExactlyInstanceOf(OCSPCertificateException.class)
                .hasMessageContaining("not equal to the configured designated OCSP responder certificate");
        assertRequestReachedResponder();
    }

    @Test
    void whenAiaResponderLacksSigningUsage_thenFailurePreservesCertificateCause() throws Exception {
        responder.replaceResponderCertificate(false);
        final var checker = customChecker(null);

        assertThatThrownBy(() -> checker.validateCertificateNotRevoked(responder.subject(), responder.issuer()))
                .isInstanceOf(CertificateRevocationCheckFailedException.class)
                .hasMessageContaining(responder.aiaUri().toString())
                .cause()
                .isExactlyInstanceOf(OCSPCertificateException.class)
                .hasMessageContaining("does not contain the Key Usage extension required for OCSP response signing");
        assertThat(responder.requestCount()).isEqualTo(1);
        assertThat(responder.receivedPath()).isEqualTo("/aia");
    }

    @Test
    void whenAiaResponderIsDelegatedBySubjectIssuer_thenValidationSucceeds() throws Exception {
        final var checker = customChecker(null);

        assertThat(checker.validateCertificateNotRevoked(responder.subject(), responder.issuer()))
                .singleElement().extracting(RevocationInfo::ocspResponderUri).isEqualTo(responder.aiaUri());
        assertThat(responder.receivedPath()).isEqualTo("/aia");
    }

    @Test
    void whenAiaResponseIsSignedBySubjectIssuer_thenValidationSucceeds() throws Exception {
        responder.close();
        responder = new LocalOcspResponder();
        responder.startWithIntermediate();
        assertThat(responder.issuer().getExtendedKeyUsage()).isNull();
        responder.useIssuerAsResponder();
        final var checker = customChecker(null, List.of(responder.root()), List.of(responder.issuer()));

        final List<RevocationInfo> info = CertificateValidator.validateCertificateTrustAndRevocation(
                responder.subject(),
                CertificateValidator.buildTrustAnchorsFromCertificates(List.of(responder.root())),
                CertificateValidator.buildCertStoreFromCertificates(List.of(responder.issuer())),
                Date.from(responder.now()), RevocationMode.CUSTOM_CHECKER, checker, null, true);

        assertThat(info)
                .singleElement().extracting(RevocationInfo::ocspResponderUri).isEqualTo(responder.aiaUri());
        assertThat(responder.requestCount()).isEqualTo(1);
        assertThat(responder.receivedPath()).isEqualTo("/aia");
    }

    @Test
    void whenTrustAnchorIsAboveDirectIssuer_thenAiaOcspValidationUsesIntermediate() throws Exception {
        responder.close();
        responder = new LocalOcspResponder();
        responder.startWithIntermediate();
        final var checker = customChecker(null, List.of(responder.root()), List.of(responder.issuer()));

        final List<RevocationInfo> info = CertificateValidator.validateCertificateTrustAndRevocation(
                responder.subject(),
                CertificateValidator.buildTrustAnchorsFromCertificates(List.of(responder.root())),
                CertificateValidator.buildCertStoreFromCertificates(List.of(responder.issuer())),
                Date.from(responder.now()), RevocationMode.CUSTOM_CHECKER, checker, null, true);

        assertThat(info).singleElement().extracting(RevocationInfo::ocspResponderUri).isEqualTo(responder.aiaUri());
        assertThat(responder.requestCount()).isEqualTo(1);
        assertThat(responder.receivedPath()).isEqualTo("/aia");
    }

    @Test
    void whenAiaRequestUsesRootInsteadOfIntermediate_thenResponderRejectsCertificateId() throws Exception {
        responder.close();
        responder = new LocalOcspResponder();
        responder.startWithIntermediate();
        final var checker = customChecker(null, List.of(responder.root()), List.of(responder.issuer()));

        assertThatThrownBy(() -> checker.validateCertificateNotRevoked(responder.subject(), responder.root()))
                .isInstanceOf(UserCertificateOCSPCheckFailedException.class)
                .hasMessageContaining("Response status: unauthorized");
        assertThat(responder.requestCount()).isEqualTo(1);
        assertThat(responder.receivedPath()).isEqualTo("/aia");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void whenAiaResponderIsDelegatedByAnotherTrustedCA_thenValidationFails(boolean sameIssuerName) throws Exception {
        responder.replaceResponderCertificateFromDifferentIssuer(sameIssuerName);
        final var checker = customChecker(null, List.of(responder.issuer(), responder.otherIssuer()));

        assertThatThrownBy(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                responder.subject(),
                CertificateValidator.buildTrustAnchorsFromCertificates(List.of(responder.issuer())),
                CertificateValidator.buildCertStoreFromCertificates(List.of(responder.issuer())),
                Date.from(responder.now()), RevocationMode.CUSTOM_CHECKER, checker, null, true))
                .isInstanceOf(CertificateRevocationCheckFailedException.class)
                .cause()
                .isInstanceOf(OCSPCertificateException.class);
        assertThat(responder.requestCount()).isEqualTo(1);
        assertThat(responder.receivedPath()).isEqualTo("/aia");
    }

    private OcspCertificateRevocationChecker customChecker(DesignatedOcspServiceConfiguration designated) throws Exception {
        return customChecker(designated, List.of(responder.issuer()));
    }

    private OcspCertificateRevocationChecker customChecker(DesignatedOcspServiceConfiguration designated,
                                                           List<X509Certificate> authorities) throws Exception {
        return customChecker(designated, authorities, authorities);
    }

    private OcspCertificateRevocationChecker customChecker(DesignatedOcspServiceConfiguration designated,
                                                           List<X509Certificate> anchors,
                                                           List<X509Certificate> intermediates) throws Exception {
        return new OcspCertificateRevocationChecker(
                OcspClientImpl.build(Duration.ofSeconds(2)),
                new OcspServiceProvider(designated, new AiaOcspServiceConfiguration(Set.of(),
                        CertificateValidator.buildTrustAnchorsFromCertificates(anchors),
                        CertificateValidator.buildCertStoreFromCertificates(intermediates),
                        OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE, OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE)),
                OcspCertificateRevocationChecker.DEFAULT_TIME_SKEW);
    }

    private List<RevocationInfo> validate() throws Exception {
        return validate(true);
    }

    private List<RevocationInfo> validate(boolean nonceEnabled) throws Exception {
        final var checker = customChecker(new DesignatedOcspServiceConfiguration(
                responder.designatedUri(), responder.responderCertificate(), List.of(responder.issuer()), nonceEnabled,
                OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE, OcspCertificateRevocationChecker.DEFAULT_NEXT_UPDATE_AGE));
        return CertificateValidator.validateCertificateTrustAndRevocation(
                responder.subject(),
                CertificateValidator.buildTrustAnchorsFromCertificates(List.of(responder.issuer())),
                CertificateValidator.buildCertStoreFromCertificates(List.of(responder.issuer())),
                Date.from(responder.now()), RevocationMode.CUSTOM_CHECKER, checker, null, nonceEnabled);
    }

    private void assertRequestReachedResponder() {
        assertThat(responder.requestCount()).isPositive();
        assertThat(responder.receivedRequest().getRequestList()).hasSize(1);
        assertThat(responder.receivedRequest().getRequestList()[0].getCertID().getSerialNumber())
                .isEqualTo(responder.subject().getSerialNumber());
        assertThat(responder.receivedPath()).startsWith("/designated");
    }
}
