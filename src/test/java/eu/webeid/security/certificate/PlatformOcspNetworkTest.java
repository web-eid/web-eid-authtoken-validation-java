// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import eu.webeid.security.exceptions.CertificateRevocationCheckFailedException;
import eu.webeid.security.exceptions.CertificateRevokedException;
import eu.webeid.security.testutil.LocalOcspResponder;
import eu.webeid.security.testutil.LocalOcspResponder.Reply;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Exercises the platform PKIX checker against a local, signing OCSP responder. */
class PlatformOcspNetworkTest {

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
        assertThat(info).isEmpty();
    }

    @Test
    void whenPlatformMakesTwoChecks_thenRequestsContainDifferent32ByteNonces() throws Exception {
        validate();
        final byte[] firstNonce = responder.requestNonce();
        validate();

        assertThat(responder.requestCount()).isEqualTo(2);
        assertThat(firstNonce).hasSize(32).isNotEqualTo(responder.requestNonce());
        assertThat(responder.requestNonce()).hasSize(32);
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

    private List<RevocationInfo> validate() throws Exception {
        return CertificateValidator.validateCertificateTrustAndRevocation(
                responder.subject(),
                CertificateValidator.buildTrustAnchorsFromCertificates(List.of(responder.issuer())),
                CertificateValidator.buildCertStoreFromCertificates(List.of(responder.issuer())),
                Date.from(responder.now()), RevocationMode.PLATFORM_OCSP, null, null, true);
    }

    private void assertRequestReachedResponder() {
        assertThat(responder.requestCount()).isPositive();
        assertThat(responder.receivedRequest().getRequestList()).hasSize(1);
        assertThat(responder.receivedRequest().getRequestList()[0].getCertID().getSerialNumber())
                .isEqualTo(responder.subject().getSerialNumber());
        assertThat(responder.receivedPath()).startsWith("/aia");
    }
}
