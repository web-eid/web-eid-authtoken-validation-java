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

package eu.webeid.resilientocsp;

import eu.webeid.ocsp.OcspCertificateRevocationChecker;
import eu.webeid.ocsp.client.OcspClient;
import eu.webeid.ocsp.exceptions.OCSPClientException;
import eu.webeid.ocsp.exceptions.UserCertificateOCSPException;
import eu.webeid.ocsp.service.FallbackOcspService;
import eu.webeid.ocsp.service.OcspService;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.resilientocsp.ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateOCSPCheckFailedException;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateRevokedException;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.retry.RetryConfig;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_AUTH_TOKEN;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_CHALLENGE_NONCE;
import static eu.webeid.security.testutil.AuthTokenValidators.getDefaultAuthTokenValidatorBuilder;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.DateMocker.mockDate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static eu.webeid.security.testutil.ResourceUtil.bytesFromResource;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ResilientOcspCertificateRevocationCheckerTest {

    private static final URI PRIMARY_URI = URI.create("http://primary.ocsp.test");
    private static final URI FALLBACK_URI = URI.create("http://fallback.ocsp.test");
    private static final URI SECOND_FALLBACK_URI = URI.create("http://second-fallback.ocsp.test");

    private static final Duration LONG_THIS_UPDATE_AGE = Duration.ofDays(365 * 10);
    private static final Duration LONG_NEXT_UPDATE_AGE = Duration.ofDays(365 * 10);

    // The OCSP DER fixtures do not share one thisUpdate. Each fixture carries its own:
    //   ocsp_response.der          2021-09-17T18:25:24
    //   ocsp_response_revoked.der  2021-09-18T00:13:43
    //   ocsp_response_unknown.der  2021-09-18T00:16:25
    // The two constants below belong to ocsp_response.der, and every test that uses them pairs them with
    // that fixture. Do not pair them with the other two fixtures: a clock set from these values is earlier
    // than their thisUpdate by more than the allowed time skew, so the library rejects the response as
    // issued too far in the future and the test fails. The unknown-status tests use
    // WITHIN_RESPONDER_CERT_VALIDITY instead, and the revoked-status tests do not mock the clock at all.
    private static final String DER_THIS_UPDATE = "2021-09-17T18:25:24";
    private static final String FIVE_MIN_AFTER_THIS_UPDATE = "2021-09-17T18:30:24";
    // Used by the unknown-status tests, where the age limit is the relaxed LONG_THIS_UPDATE_AGE, so only the
    // OCSP responder certificate validity window matters (this value sits within it).
    private static final String WITHIN_RESPONDER_CERT_VALIDITY = "2021-09-18T00:16:25";

    private X509Certificate estEid2018Cert;
    private X509Certificate testEsteid2018CA;

    private OCSPResp ocspRespGood;
    private OCSPResp ocspRespRevoked;
    private OCSPResp ocspRespUnknown;

    @BeforeEach
    void setUp() throws Exception {
        estEid2018Cert = getJaakKristjanEsteid2018Cert();
        testEsteid2018CA = getTestEsteid2018CA();
        ocspRespGood = new OCSPResp(bytesFromResource("ocsp_response.der"));
        ocspRespRevoked = new OCSPResp(bytesFromResource("ocsp_response_revoked.der"));
        ocspRespUnknown = new OCSPResp(bytesFromResource("ocsp_response_unknown.der"));
    }

    @Test
    void whenMultipleValidationCalls_thenPreviousResultsAreNotModified() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException("Primary OCSP service unavailable (call1)"))
            .thenThrow(new OCSPClientException("Primary OCSP service unavailable (call2)"));
        when(ocspClient.request(eq(FALLBACK_URI), any()))
            .thenThrow(new OCSPClientException("Fallback OCSP service unavailable (call1)"))
            .thenThrow(new OCSPClientException("Fallback OCSP service unavailable (call2)"));
        when(ocspClient.request(eq(SECOND_FALLBACK_URI), any()))
            .thenThrow(new OCSPClientException("Secondary fallback OCSP service unavailable (call1)"))
            .thenThrow(new OCSPClientException("Secondary fallback OCSP service unavailable (call2)"));
        ResilientOcspCertificateRevocationChecker resilientChecker = checkerBuilder(ocspClient).build();
        AuthTokenValidator validator = getDefaultAuthTokenValidatorBuilder()
            .withCertificateRevocationChecker(resilientChecker)
            .build();
        WebEidAuthToken authToken = validator.parse(VALID_AUTH_TOKEN);

        ResilientUserCertificateOCSPCheckFailedException ex1 = assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> validator.validate(authToken, VALID_CHALLENGE_NONCE))
            .actual();
        List<RevocationInfo> revocationInfo1 = ex1.getValidationInfo().revocationInfoList();
        assertThat(revocationInfo1).hasSize(3);
        assertThat(revocationInfo1)
            .extracting(ri -> ((OCSPClientException) ri.ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR)).getMessage())
            .containsExactly(
                "Primary OCSP service unavailable (call1)",
                "Fallback OCSP service unavailable (call1)",
                "Secondary fallback OCSP service unavailable (call1)"
            );
        ResilientUserCertificateOCSPCheckFailedException ex2 = assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> validator.validate(authToken, VALID_CHALLENGE_NONCE))
            .actual();
        List<RevocationInfo> revocationInfo2 = ex2.getValidationInfo().revocationInfoList();
        assertThat(revocationInfo2).hasSize(3);
        assertThat(revocationInfo2)
            .extracting(ri -> ((OCSPClientException) ri.ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR)).getMessage())
            .containsExactly(
                "Primary OCSP service unavailable (call2)",
                "Fallback OCSP service unavailable (call2)",
                "Secondary fallback OCSP service unavailable (call2)"
            );
        assertThat(revocationInfo1).hasSize(3);
        assertThat(revocationInfo1)
            .extracting(ri -> ((OCSPClientException) ri.ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR)).getMessage())
            .containsExactly(
                "Primary OCSP service unavailable (call1)",
                "Fallback OCSP service unavailable (call1)",
                "Secondary fallback OCSP service unavailable (call1)"
            );
    }

    @Test
    void whenMaxAttemptsIsTwoAndAllCallsFail_thenRevocationInfoListRecordsRetriedPrimaryThenBothFallbacks() throws Exception {
        // The Retry decorator wraps only the primary supplier, so maxAttempts(2) records two primary attempts
        // before the two fallbacks. Asserting the responder order (primary, primary, fallback, second fallback)
        // and the two distinct primary error messages proves the fourth element comes from the retried primary,
        // not just that the list happens to have four elements.
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException("primary attempt 1"))
            .thenThrow(new OCSPClientException("primary attempt 2"));
        when(ocspClient.request(eq(FALLBACK_URI), any()))
            .thenThrow(new OCSPClientException());
        when(ocspClient.request(eq(SECOND_FALLBACK_URI), any()))
            .thenThrow(new OCSPClientException());

        RetryConfig retryConfig = RetryConfig.custom()
            .maxAttempts(2)
            .build();

        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withRetryConfig(retryConfig).build();
        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();
                assertThat(revocationInfoList).hasSize(4);
                assertThat(revocationInfoList).extracting(RevocationInfo::ocspResponderUri)
                    .containsExactly(PRIMARY_URI, PRIMARY_URI, FALLBACK_URI, SECOND_FALLBACK_URI);
                assertThat(((OCSPClientException) revocationInfoList.get(0).ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR)).getMessage())
                    .isEqualTo("primary attempt 1");
                assertThat(((OCSPClientException) revocationInfoList.get(1).ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR)).getMessage())
                    .isEqualTo("primary attempt 2");
            });
    }

    @Test
    void whenMaxAttemptsIsTwoAndFirstCallFails_thenTwoCallsToPrimaryShouldBeRecorded() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException("Primary OCSP service unavailable (call1)"))
            .thenReturn(ocspRespGood);

        RetryConfig retryConfig = RetryConfig.custom()
            .maxAttempts(2)
            .build();

        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withRetryConfig(retryConfig).build();
        List<RevocationInfo> revocationInfoList = checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        assertThat(revocationInfoList.size()).isEqualTo(2);

        Map<String, Object> firstResponseAttributes = revocationInfoList.get(0).ocspResponseAttributes();
        OCSPClientException ex1 = (OCSPClientException) firstResponseAttributes.get(RevocationInfo.KEY_OCSP_ERROR);
        assertThat(ex1.getMessage()).isEqualTo("Primary OCSP service unavailable (call1)");

        assertThat(getCertificateStatus(revocationInfoList.get(1))).isEqualTo(CertificateStatus.GOOD);
    }

    @Test
    void whenPrimaryReturnsRevoked_thenRevocationInfoListShouldHaveOneElementAndItShouldHaveRevokedStatus() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenReturn(ocspRespRevoked);

        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).build();
        assertThatExceptionOfType(ResilientUserCertificateRevokedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();
                assertThat(revocationInfoList.size()).isEqualTo(1);
                assertThat(getCertificateStatus(revocationInfoList.get(0))).isInstanceOf(RevokedStatus.class);
            });
    }

    @Test
    void whenCallerConfigRecordsAllExceptions_thenRevokedVerdictDoesNotOpenCircuitBreaker() throws Exception {
        // A revoked verdict is a definitive OCSP answer, so it must never count as a circuit breaker failure.
        // CircuitBreakerConfig.from() copies both the record predicate and the recordExceptions array of the
        // caller configuration, and the array is combined with our own predicate by OR. A caller that records
        // every exception must therefore not be able to make a revoked verdict open the circuit breaker.
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenReturn(ocspRespRevoked);
        when(ocspClient.request(eq(FALLBACK_URI), any()))
            .thenReturn(ocspRespGood);
        CircuitBreakerConfig callerConfig = CircuitBreakerConfig.custom()
            .recordExceptions(Throwable.class)
            .slidingWindowSize(2)
            .minimumNumberOfCalls(2)
            .failureRateThreshold(50)
            .permittedNumberOfCallsInHalfOpenState(1)
            .build();

        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withFallbacks(FALLBACK_URI)
            .withCircuitBreakerConfig(callerConfig)
            .build();

        // The configuration above would open the circuit breaker after two recorded failures. All three calls
        // must still report revocation from the primary service, and no call must reach the fallback service.
        for (int i = 0; i < 3; i++) {
            assertThatExceptionOfType(ResilientUserCertificateRevokedException.class)
                .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA));
        }
        verify(ocspClient, times(3)).request(eq(PRIMARY_URI), any());
        verify(ocspClient, never()).request(eq(FALLBACK_URI), any());
    }

    @Test
    void whenOneFallbackIsConfiguredAndPrimaryAndFallbackFail_thenRevocationInfoListShouldHaveTwoElements() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException());
        when(ocspClient.request(eq(FALLBACK_URI), any()))
            .thenThrow(new OCSPClientException());

        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withFallbacks(FALLBACK_URI).build();

        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();
                assertThat(revocationInfoList.size()).isEqualTo(2);
            });
    }

    @Test
    void whenNoFallbacksAreConfigured_thenRevocationInfoListShouldHaveOneElement() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException());

        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withoutFallbacks().build();

        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();
                assertThat(revocationInfoList.size()).isEqualTo(1);
            });
    }

    @Test
    void whenPrimaryReturnsUnauthorizedOcspResponseStatus_thenWrapsResponseStatusError() throws Exception {
        OCSPResp ocspRespStatusUnauthorized = new OCSPResp(bytesFromResource("ocsp_response_unauthorized.der"));

        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenReturn(ocspRespStatusUnauthorized);

        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).build();
        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                Map<String, Object> responseAttributes = ex.getValidationInfo().revocationInfoList().get(0).ocspResponseAttributes();
                ResilientUserCertificateOCSPCheckFailedException firstException = (ResilientUserCertificateOCSPCheckFailedException) responseAttributes.get(RevocationInfo.KEY_OCSP_ERROR);
                assertThat(firstException.getMessage()).isEqualTo("Response status: unauthorized");
            });
    }

    @Test
    void whenCertificateIdComputationFails_thenThrows() throws Exception {
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(mock(OcspClient.class)).build();
        X509Certificate badIssuer = mock(X509Certificate.class);
        CertificateEncodingException encodingException = new CertificateEncodingException("bad issuer");
        when(badIssuer.getEncoded()).thenThrow(encodingException);

        assertThatExceptionOfType(UserCertificateOCSPException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, badIssuer))
            .isExactlyInstanceOf(UserCertificateOCSPException.class)
            .withMessage("Unable to compute certificateId for subject certificate")
            .withCause(encodingException);
    }

    @Test
    void whenNoFallbackConfiguredAndPrimarySucceeds_thenPrimaryResponseIsReturned() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(ocspRespGood);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withoutFallbacks().build();

        List<RevocationInfo> revocationInfoList = checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

        assertThat(revocationInfoList).hasSize(1);
        assertThat(revocationInfoList.get(0).ocspResponderUri()).isEqualTo(PRIMARY_URI);
        assertThat(getCertificateStatus(revocationInfoList.get(0))).isEqualTo(CertificateStatus.GOOD);
    }

    @Test
    void whenPrimaryReturnsRevoked_thenNotRetried() throws Exception {
        // A revoked verdict is a definitive answer; the Retry config ignores
        // ResilientUserCertificateRevokedException, so the primary is queried exactly once even with maxAttempts(2).
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(ocspRespRevoked);
        RetryConfig retryConfig = RetryConfig.custom().maxAttempts(2).waitDuration(Duration.ZERO).build();
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withRetryConfig(retryConfig).build();

        assertThatExceptionOfType(ResilientUserCertificateRevokedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA));
        verify(ocspClient, times(1)).request(eq(PRIMARY_URI), any());
        verify(ocspClient, never()).request(eq(FALLBACK_URI), any());
    }

    @Test
    void whenPrimaryReturnsRevoked_thenCircuitBreakerDoesNotOpen() throws Exception {
        // The CircuitBreaker config ignores ResilientUserCertificateRevokedException, so repeated revoked
        // verdicts are not counted as failures and the breaker stays closed. With a config that would trip
        // after two real failures, the primary is still queried on the third call.
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(ocspRespRevoked);
        CircuitBreakerConfig tightCircuitBreakerConfig = CircuitBreakerConfig.custom()
            .slidingWindowSize(2)
            .minimumNumberOfCalls(2)
            .failureRateThreshold(50)
            .permittedNumberOfCallsInHalfOpenState(1)
            .build();
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withFallbacks(FALLBACK_URI)
            .withCircuitBreakerConfig(tightCircuitBreakerConfig)
            .build();

        assertThatExceptionOfType(ResilientUserCertificateRevokedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA));
        assertThatExceptionOfType(ResilientUserCertificateRevokedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA));
        assertThatExceptionOfType(ResilientUserCertificateRevokedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA));

        verify(ocspClient, times(3)).request(eq(PRIMARY_URI), any());
        verify(ocspClient, never()).request(eq(FALLBACK_URI), any());
    }

    @Test
    void whenPrimaryFailsAndFirstFallbackReturnsRevoked_thenListContainsBothEntries() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException("Primary OCSP service unavailable"));
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenReturn(ocspRespRevoked);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).build();

        assertThatExceptionOfType(ResilientUserCertificateRevokedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .withMessage("User certificate has been revoked")
            .satisfies(ex -> {
                List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();
                assertThat(revocationInfoList).hasSize(2);
                assertThat(revocationInfoList).extracting(RevocationInfo::ocspResponderUri)
                    .containsExactly(PRIMARY_URI, FALLBACK_URI);
                assertThat(revocationInfoList.get(0).ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR))
                    .isInstanceOf(OCSPClientException.class);
                assertThat(getCertificateStatus(revocationInfoList.get(1))).isInstanceOf(RevokedStatus.class);
            });
        verify(ocspClient, never()).request(eq(SECOND_FALLBACK_URI), any());
    }

    @Test
    void whenPrimaryReturnsMissingBasicOcspResponse_thenThrows() throws Exception {
        OCSPResp response = mock(OCSPResp.class);
        when(response.getStatus()).thenReturn(OCSPResponseStatus.SUCCESSFUL);
        when(response.getResponseObject()).thenReturn(null);
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(response);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).build();

        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                Map<String, Object> primaryAttributes = ex.getValidationInfo().revocationInfoList().get(0).ocspResponseAttributes();
                ResilientUserCertificateOCSPCheckFailedException primaryError =
                    (ResilientUserCertificateOCSPCheckFailedException) primaryAttributes.get(RevocationInfo.KEY_OCSP_ERROR);
                assertThat(primaryError.getMessage()).isEqualTo("Missing or unsupported Basic OCSP Response");
            });
    }

    @Test
    void whenPrimaryReturnsUnknown_thenFallbackHandlesTheCall() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(ocspRespUnknown);
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenReturn(ocspRespGood);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).build();

        try (var mockedClock = mockStaticClockAt(WITHIN_RESPONDER_CERT_VALIDITY)) {
            List<RevocationInfo> revocationInfoList = checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

            assertThat(revocationInfoList).hasSize(2);
            verify(ocspClient).request(eq(FALLBACK_URI), any());
        }
    }

    @Test
    void whenNonceEnabledAndResponseNonceDiffers_thenThrows() throws Exception {
        // primaryService advertises nonce support; ocspRespGood was signed with a different nonce.
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(ocspRespGood);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withoutFallbacks()
            .withPrimaryNonceSupport()
            .build();

        try (var ignored = mockStaticClockAt(DER_THIS_UPDATE)) {
            assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
                .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
                .satisfies(ex -> {
                    Throwable originalError = (Throwable) ex.getValidationInfo().revocationInfoList().get(0)
                        .ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR);
                    assertThat(originalError).hasMessageContaining("OCSP request and response nonces differ");
                });
        }
    }

    @Test
    void whenCircuitBreakerIsOpenAndRecoveryTimeElapses_thenPrimaryIsTriedAgainInHalfOpenState() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException("Primary OCSP service unavailable"))
            .thenThrow(new OCSPClientException("Primary OCSP service unavailable"))
            .thenReturn(ocspRespGood);
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenReturn(ocspRespGood);
        CircuitBreakerConfig recoverableCircuitBreakerConfig = CircuitBreakerConfig.custom()
            .slidingWindowSize(2)
            .minimumNumberOfCalls(2)
            .failureRateThreshold(50)
            .waitDurationInOpenState(Duration.ofSeconds(1))
            .permittedNumberOfCallsInHalfOpenState(1)
            .build();
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withFallbacks(FALLBACK_URI)
            .withCircuitBreakerConfig(recoverableCircuitBreakerConfig)
            .build();

        checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

        List<RevocationInfo> openStateRevocationInfoList =
            checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

        assertThat(openStateRevocationInfoList).hasSize(1);
        assertThat(openStateRevocationInfoList.get(0).ocspResponderUri()).isEqualTo(FALLBACK_URI);
        verify(ocspClient, times(2)).request(eq(PRIMARY_URI), any());

        await().atMost(Duration.ofSeconds(5))
            .pollInterval(Duration.ofMillis(50))
            .untilAsserted(() -> {
                List<RevocationInfo> halfOpenRevocationInfoList =
                    checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
                assertThat(halfOpenRevocationInfoList).hasSize(1);
                assertThat(halfOpenRevocationInfoList.get(0).ocspResponderUri()).isEqualTo(PRIMARY_URI);
            });
        verify(ocspClient, times(3)).request(eq(PRIMARY_URI), any());
    }

    @Test
    void whenPrimaryAnswersInHalfOpenState_thenStatisticsReportHalfOpenState() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException("Primary OCSP service unavailable"))
            .thenThrow(new OCSPClientException("Primary OCSP service unavailable"))
            .thenReturn(ocspRespGood);
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenReturn(ocspRespGood);
        CircuitBreakerConfig recoverableCircuitBreakerConfig = CircuitBreakerConfig.custom()
            .slidingWindowSize(2)
            .minimumNumberOfCalls(2)
            .failureRateThreshold(50)
            .waitDurationInOpenState(Duration.ofSeconds(1))
            .permittedNumberOfCallsInHalfOpenState(1)
            .build();
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withFallbacks(FALLBACK_URI)
            .withCircuitBreakerConfig(recoverableCircuitBreakerConfig)
            .build();
        // The first two calls fail on the primary and trip the breaker.
        checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        // Let the open state expire without calling the checker, so that the next call is the one that the
        // circuit breaker permits in half open state.
        await().pollDelay(waitLongerThan(Duration.ofSeconds(1)))
            .atMost(Duration.ofSeconds(10))
            .until(() -> true);

        List<RevocationInfo> revocationInfoList =
            checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

        assertThat(revocationInfoList.get(0).ocspResponderUri()).isEqualTo(PRIMARY_URI);
        // The primary answered, so the circuit breaker permitted the call in half open state.
        // The reported state must not contradict which responder answered.
        assertThat(getCircuitBreakerStatistics(revocationInfoList.get(0)).state())
            .isEqualTo(CircuitBreaker.State.HALF_OPEN);
    }

    @Test
    void whenPrimaryFailsInHalfOpenStateAndFallbackAnswers_thenStatisticsReportHalfOpenState() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(new OCSPClientException("Primary OCSP service unavailable"));
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenReturn(ocspRespGood);
        CircuitBreakerConfig recoverableCircuitBreakerConfig = CircuitBreakerConfig.custom()
            .slidingWindowSize(2)
            .minimumNumberOfCalls(2)
            .failureRateThreshold(50)
            .waitDurationInOpenState(Duration.ofSeconds(1))
            .permittedNumberOfCallsInHalfOpenState(1)
            .build();
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withFallbacks(FALLBACK_URI)
            .withCircuitBreakerConfig(recoverableCircuitBreakerConfig)
            .build();
        // The first two calls fail on the primary and trip the breaker.
        checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        // Let the open state expire without calling the checker, so that the next call is the one that the
        // circuit breaker permits in half open state.
        await().pollDelay(waitLongerThan(Duration.ofSeconds(1)))
            .atMost(Duration.ofSeconds(10))
            .until(() -> true);

        List<RevocationInfo> revocationInfoList =
            checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        // The next call finds the freshly re-opened breaker: the primary is not called and the statistics
        // are a new snapshot that reports the OPEN state that rejected the call.
        List<RevocationInfo> reopenedRevocationInfoList =
            checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

        assertThat(revocationInfoList).hasSize(2);
        assertThat(revocationInfoList.get(0).ocspResponderUri()).isEqualTo(PRIMARY_URI);
        assertThat(revocationInfoList.get(1).ocspResponderUri()).isEqualTo(FALLBACK_URI);
        // The breaker permitted the primary call in half open state and re-opened when the call failed,
        // before the fallback ran. The statistics must keep the snapshot taken when the primary request
        // started (HALF_OPEN): neither the expired OPEN state that a snapshot taken before the call would
        // report, nor the re-opened OPEN state that a capture in the fallback path would take.
        assertThat(getCircuitBreakerStatistics(revocationInfoList.get(0)).state())
            .isEqualTo(CircuitBreaker.State.HALF_OPEN);
        assertThat(reopenedRevocationInfoList).hasSize(1);
        assertThat(reopenedRevocationInfoList.get(0).ocspResponderUri()).isEqualTo(FALLBACK_URI);
        assertThat(getCircuitBreakerStatistics(reopenedRevocationInfoList.get(0)).state())
            .isEqualTo(CircuitBreaker.State.OPEN);
        verify(ocspClient, times(3)).request(eq(PRIMARY_URI), any());
    }

    @Test
    void whenPrimaryFailsInClosedState_thenStatisticsDoNotIncludeCurrentCallFailure() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(new OCSPClientException("Primary OCSP service unavailable"));
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenReturn(ocspRespGood);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withFallbacks(FALLBACK_URI)
            .build();

        List<RevocationInfo> firstCallRevocationInfoList =
            checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        List<RevocationInfo> secondCallRevocationInfoList =
            checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

        // The statistics are captured when the primary request starts, so the outcome of the very call they
        // are attached to is not yet included: the first call reports no recorded calls at all and the
        // second call reports only the first call's failure.
        CircuitBreakerStatistics firstCallStatistics =
            getCircuitBreakerStatistics(firstCallRevocationInfoList.get(0));
        assertThat(firstCallStatistics.state()).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(firstCallStatistics.numberOfBufferedCalls()).isZero();
        assertThat(firstCallStatistics.numberOfFailedCalls()).isZero();
        CircuitBreakerStatistics secondCallStatistics =
            getCircuitBreakerStatistics(secondCallRevocationInfoList.get(0));
        assertThat(secondCallStatistics.state()).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(secondCallStatistics.numberOfBufferedCalls()).isEqualTo(1);
        assertThat(secondCallStatistics.numberOfFailedCalls()).isEqualTo(1);
    }

    @Test
    void whenOcspRequestFailsWithStatusCode_thenRevocationInfoContainsHttpStatusCodeAndResponseBody() throws Exception {
        byte[] responseBody = "error".getBytes();
        OCSPClientException ocspClientException = new OCSPClientException("OCSP request was not successful", responseBody, 503);
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(ocspClientException);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withoutFallbacks().build();

        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                Map<String, Object> attributes = ex.getValidationInfo().revocationInfoList().get(0).ocspResponseAttributes();
                assertThat(attributes.get(RevocationInfo.KEY_HTTP_STATUS_CODE)).isEqualTo(503);
                assertThat(attributes.get(RevocationInfo.KEY_OCSP_RESPONSE)).isEqualTo(responseBody);
            });
    }

    @Test
    void whenPrimaryThrowsRuntimeExceptionThatIsNotOCSPClientException_thenWrapsAsResilientUserCertificateOCSPCheckFailedException() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(new NullPointerException());
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenThrow(new NullPointerException());
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withFallbacks(FALLBACK_URI).build();

        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                assertThat(ex.getValidationInfo().revocationInfoList()).hasSize(2);
                Throwable primaryError = (Throwable) ex.getValidationInfo().revocationInfoList().get(0)
                    .ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR);
                assertThat(primaryError).isInstanceOf(NullPointerException.class);
            });
    }

    @Test
    void whenOcspClientReturnsNullResponse_thenWrapsAsResilientUserCertificateOCSPCheckFailedException() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(null);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withoutFallbacks().build();

        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                Throwable primaryError = (Throwable) ex.getValidationInfo().revocationInfoList().get(0)
                    .ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR);
                assertThat(primaryError).isInstanceOf(NullPointerException.class);
            });
    }

    @Test
    void whenPrimaryOcspServiceAccessLocationIsNull_thenWrapsAsResilientUserCertificateOCSPCheckFailedException() throws Exception {
        NullPointerException nullUriRejectedByClient = new NullPointerException("uri");
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(isNull(), any())).thenThrow(nullUriRejectedByClient);
        OcspService primaryService = mock(OcspService.class);
        when(primaryService.getAccessLocation()).thenReturn(null);
        when(primaryService.doesSupportNonce()).thenReturn(false);
        when(primaryService.getFallbackService()).thenReturn(Optional.empty());
        OcspServiceProvider ocspServiceProvider = mock(OcspServiceProvider.class);
        when(ocspServiceProvider.getService(any(), any())).thenReturn(primaryService);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withOcspServiceProvider(ocspServiceProvider)
            .build();

        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                RevocationInfo revocationInfo = ex.getValidationInfo().revocationInfoList().get(0);
                assertThat(revocationInfo.ocspResponderUri()).isNull();
                Map<String, Object> attributes = revocationInfo.ocspResponseAttributes();
                assertThat(attributes.get(RevocationInfo.KEY_OCSP_ERROR)).isSameAs(nullUriRejectedByClient);
                // getOcspRequest() builds the request before the responder is contacted, so the request
                // is recorded even when the call itself fails.
                assertThat(attributes).containsKey(RevocationInfo.KEY_OCSP_REQUEST);
                assertThat(attributes).doesNotContainKey(RevocationInfo.KEY_OCSP_RESPONSE);
            });
        verify(ocspClient).request(isNull(), any());
    }

    @Test
    void whenPrimarySucceeds_thenRevocationInfoListContainsExpectedResponderUrisAndAttributes() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(ocspRespGood);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).build();

        List<RevocationInfo> revocationInfoList = checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

        assertThat(revocationInfoList).hasSize(1);

        RevocationInfo primary = revocationInfoList.get(0);
        assertThat(primary.ocspResponderUri()).isEqualTo(PRIMARY_URI);
        assertThat(getCertificateStatus(primary)).isEqualTo(CertificateStatus.GOOD);
        assertThat(primary.ocspResponseAttributes())
            .doesNotContainKey(RevocationInfo.KEY_OCSP_ERROR)
            .containsKey(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS)
            .containsKey(RevocationInfo.KEY_REQUEST_DURATION)
            .containsKey(RevocationInfo.KEY_OCSP_RESPONSE_TIME);
        assertThat(primary.ocspResponseAttributes().get(RevocationInfo.KEY_REQUEST_DURATION)).isInstanceOf(Duration.class);
        assertThat((Duration) primary.ocspResponseAttributes().get(RevocationInfo.KEY_REQUEST_DURATION))
            .isGreaterThanOrEqualTo(Duration.ZERO);
        assertThat(primary.ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_RESPONSE_TIME)).isInstanceOf(Instant.class);
    }

    @Test
    void whenPrimaryFailsAndFirstFallbackSucceeds_thenRevocationInfoListContainsExpectedResponderUrisAndAttributes() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(new OCSPClientException("primary"));
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenReturn(ocspRespGood);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).build();

        List<RevocationInfo> revocationInfoList = checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

        assertThat(revocationInfoList).hasSize(2);

        RevocationInfo primary = revocationInfoList.get(0);
        assertThat(primary.ocspResponderUri()).isEqualTo(PRIMARY_URI);
        assertThat(primary.ocspResponseAttributes())
            .containsKey(RevocationInfo.KEY_OCSP_ERROR)
            .containsKey(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);

        RevocationInfo fallback = revocationInfoList.get(1);
        assertThat(fallback.ocspResponderUri()).isEqualTo(FALLBACK_URI);
        assertThat(getCertificateStatus(fallback)).isEqualTo(CertificateStatus.GOOD);
        assertThat(fallback.ocspResponseAttributes())
            .doesNotContainKey(RevocationInfo.KEY_OCSP_ERROR)
            .doesNotContainKey(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS)
            .containsKey(RevocationInfo.KEY_REQUEST_DURATION)
            .containsKey(RevocationInfo.KEY_OCSP_RESPONSE_TIME);
        assertThat(fallback.ocspResponseAttributes().get(RevocationInfo.KEY_REQUEST_DURATION)).isInstanceOf(Duration.class);
        assertThat(fallback.ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_RESPONSE_TIME)).isInstanceOf(Instant.class);

        verify(ocspClient, never()).request(eq(SECOND_FALLBACK_URI), any());
    }

    @Test
    void whenPrimaryAndFirstFallbackFailAndSecondFallbackSucceeds_thenRevocationInfoListContainsExpectedResponderUrisAndAttributes() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(new OCSPClientException("Primary OCSP service unavailable"));
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenThrow(new OCSPClientException("Fallback OCSP service unavailable"));
        when(ocspClient.request(eq(SECOND_FALLBACK_URI), any())).thenReturn(ocspRespGood);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).build();

        List<RevocationInfo> revocationInfoList = checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

        assertThat(revocationInfoList).hasSize(3);

        RevocationInfo primary = revocationInfoList.get(0);
        assertThat(primary.ocspResponderUri()).isEqualTo(PRIMARY_URI);
        assertThat(primary.ocspResponseAttributes())
            .containsKey(RevocationInfo.KEY_OCSP_ERROR)
            .containsKey(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);

        RevocationInfo firstFallback = revocationInfoList.get(1);
        assertThat(firstFallback.ocspResponderUri()).isEqualTo(FALLBACK_URI);
        assertThat(firstFallback.ocspResponseAttributes())
            .containsKey(RevocationInfo.KEY_OCSP_ERROR)
            .doesNotContainKey(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);

        RevocationInfo secondFallback = revocationInfoList.get(2);
        assertThat(secondFallback.ocspResponderUri()).isEqualTo(SECOND_FALLBACK_URI);
        assertThat(secondFallback.ocspResponseAttributes())
            .doesNotContainKey(RevocationInfo.KEY_OCSP_ERROR)
            .doesNotContainKey(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);
    }

    @Test
    void whenAllFail_thenRevocationInfoListContainsExpectedResponderUrisAndAttributes() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(new OCSPClientException("primary"));
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenThrow(new OCSPClientException("fallback"));
        when(ocspClient.request(eq(SECOND_FALLBACK_URI), any())).thenThrow(new OCSPClientException("second"));
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).build();

        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                assertThat(ex.getValidationInfo()).isNotNull();
                List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();

                assertThat(revocationInfoList).hasSize(3);

                RevocationInfo primary = revocationInfoList.get(0);
                assertThat(primary.ocspResponderUri()).isEqualTo(PRIMARY_URI);
                assertThat(primary.ocspResponseAttributes())
                    .containsKey(RevocationInfo.KEY_OCSP_ERROR)
                    .containsKey(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);

                RevocationInfo firstFallback = revocationInfoList.get(1);
                assertThat(firstFallback.ocspResponderUri()).isEqualTo(FALLBACK_URI);
                assertThat(firstFallback.ocspResponseAttributes())
                    .containsKey(RevocationInfo.KEY_OCSP_ERROR)
                    .doesNotContainKey(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);

                RevocationInfo secondFallback = revocationInfoList.get(2);
                assertThat(secondFallback.ocspResponderUri()).isEqualTo(SECOND_FALLBACK_URI);
                assertThat(secondFallback.ocspResponseAttributes())
                    .containsKey(RevocationInfo.KEY_OCSP_ERROR)
                    .doesNotContainKey(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);
            });
    }

    @Test
    void whenPrimaryResponseIsTooOldForPrimaryAgeLimit_thenFallbackAcceptsItUnderFallbackAgeLimit() throws Exception {
        // The same response (thisUpdate 2021-09-17T18:25:24) is served by both responders and the clock is mocked
        // 5 minutes later. The primary applies the stricter 2-minute limit and rejects it as too old, while the
        // fallback applies the more lenient 10-minute limit and accepts it. This proves that each responder
        // applies the maxThisUpdateAge of its own OCSP service; swapping the two values would flip the outcome
        // and fail this test.
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(ocspRespGood);
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenReturn(ocspRespGood);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withFallbacks(FALLBACK_URI)
            .withPrimaryMaxThisUpdateAge(Duration.ofMinutes(2))
            .withFallbackMaxThisUpdateAge(Duration.ofMinutes(10))
            .build();

        try (var ignored = mockStaticClockAt(FIVE_MIN_AFTER_THIS_UPDATE)) {
            List<RevocationInfo> revocationInfoList = checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

            assertThat(revocationInfoList).hasSize(2);

            RevocationInfo primary = revocationInfoList.get(0);
            assertThat(primary.ocspResponderUri()).isEqualTo(PRIMARY_URI);
            Throwable primaryError = (Throwable) primary.ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR);
            assertThat(primaryError).hasMessageContaining("thisUpdate").hasMessageContaining("is too old");

            RevocationInfo fallback = revocationInfoList.get(1);
            assertThat(fallback.ocspResponderUri()).isEqualTo(FALLBACK_URI);
            assertThat(getCertificateStatus(fallback)).isEqualTo(CertificateStatus.GOOD);
        }
    }

    @Test
    void whenCircuitBreakerOpens_thenFallbackHandlesCallAndStatisticsReflectOpenState() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(new OCSPClientException("Primary OCSP service unavailable"));
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenReturn(ocspRespGood);
        CircuitBreakerConfig tightCircuitBreakerConfig = CircuitBreakerConfig.custom()
            .slidingWindowSize(2)
            .minimumNumberOfCalls(2)
            .failureRateThreshold(50)
            .permittedNumberOfCallsInHalfOpenState(1)
            .build();
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withFallbacks(FALLBACK_URI)
            .withCircuitBreakerConfig(tightCircuitBreakerConfig)
            .build();

        // The first two calls fail on the primary and trip the breaker; the third call sees it already open.
        checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        List<RevocationInfo> revocationInfoList = checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);

        assertThat(revocationInfoList).hasSize(1);
        assertThat(revocationInfoList.get(0).ocspResponderUri()).isEqualTo(FALLBACK_URI);
        CircuitBreakerStatistics statistics =
            (CircuitBreakerStatistics)
                revocationInfoList.get(0).ocspResponseAttributes().get(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);
        assertThat(statistics).isNotNull();
        assertThat(statistics.state()).isEqualTo(CircuitBreaker.State.OPEN);
        assertThat(statistics.numberOfFailedCalls()).isEqualTo(2);
        // The circuit breaker rejected the primary call, so the snapshot is taken when the fallback request
        // starts and includes the rejection of this very call.
        assertThat(statistics.numberOfNotPermittedCalls()).isEqualTo(1);
    }

    @Test
    void whenNoFallbackConfiguredAndPrimaryReturnsRevoked_thenRevokedPropagatesWithSingleEntry() throws Exception {
        // The no-fallback branch returns directly from request() without going through processResult, so this
        // exercises ResilientUserCertificateRevokedException propagating straight out of validateCertificateNotRevoked.
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(ocspRespRevoked);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withoutFallbacks().build();

        assertThatExceptionOfType(ResilientUserCertificateRevokedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();
                assertThat(revocationInfoList).hasSize(1);
                assertThat(revocationInfoList.get(0).ocspResponderUri()).isEqualTo(PRIMARY_URI);
                assertThat(getCertificateStatus(revocationInfoList.get(0))).isInstanceOf(RevokedStatus.class);
            });
    }

    @Test
    void whenNoFallbackConfiguredAndPrimaryReturnsUnknown_thenCheckFailedPropagates() throws Exception {
        // The unknown status fails the OCSP check.
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenReturn(ocspRespUnknown);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).withoutFallbacks().build();

        try (var ignored = mockStaticClockAt(WITHIN_RESPONDER_CERT_VALIDITY)) {
            assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
                .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
                .satisfies(ex -> assertThat(ex.getValidationInfo().revocationInfoList()).hasSize(1));
        }
    }

    @Test
    void whenNoFallbackConfigured_thenRetryAndCircuitBreakerAreNotApplied() throws Exception {
        // The class contract states retry and circuit breaker apply only when a fallback is configured. With no
        // fallback the primary must be queried exactly once (no retry) and no circuit breaker statistics attached.
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(new OCSPClientException("Primary OCSP service unavailable"));
        RetryConfig retryConfig = RetryConfig.custom().maxAttempts(2).waitDuration(Duration.ZERO).build();
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withoutFallbacks()
            .withRetryConfig(retryConfig)
            .build();

        assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();
                assertThat(revocationInfoList).hasSize(1);
                assertThat(revocationInfoList.get(0).ocspResponseAttributes())
                    .doesNotContainKey(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);
            });
        verify(ocspClient, times(1)).request(eq(PRIMARY_URI), any());
    }

    @Test
    void whenPrimaryAndFirstFallbackFailAndSecondFallbackReturnsRevoked_thenRevokedPropagates() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(new OCSPClientException("Primary OCSP service unavailable"));
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenThrow(new OCSPClientException("Fallback OCSP service unavailable"));
        when(ocspClient.request(eq(SECOND_FALLBACK_URI), any())).thenReturn(ocspRespRevoked);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient).build();

        assertThatExceptionOfType(ResilientUserCertificateRevokedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .satisfies(ex -> {
                List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();
                assertThat(revocationInfoList).hasSize(3);
                assertThat(revocationInfoList).extracting(RevocationInfo::ocspResponderUri)
                    .containsExactly(PRIMARY_URI, FALLBACK_URI, SECOND_FALLBACK_URI);
                assertThat(getCertificateStatus(revocationInfoList.get(2))).isInstanceOf(RevokedStatus.class);
            });
    }

    @Test
    void whenFallbackResponseIsTooOldForFallbackAgeLimit_thenOcspCheckFails() throws Exception {
        // The response thisUpdate is 2021-09-17T18:25:24 and the clock is mocked 5 minutes later, while the fallback
        // age limit is only 2 minutes, so the fallback rejects the response as too old. This exercises the failure
        // direction of the fallback service maxThisUpdateAge (the accepting direction is covered elsewhere).
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any())).thenThrow(new OCSPClientException("Primary OCSP service unavailable"));
        when(ocspClient.request(eq(FALLBACK_URI), any())).thenReturn(ocspRespGood);
        ResilientOcspCertificateRevocationChecker checker = checkerBuilder(ocspClient)
            .withFallbacks(FALLBACK_URI)
            .withFallbackMaxThisUpdateAge(Duration.ofMinutes(2))
            .build();

        try (var ignored = mockStaticClockAt(FIVE_MIN_AFTER_THIS_UPDATE)) {
            assertThatExceptionOfType(ResilientUserCertificateOCSPCheckFailedException.class)
                .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
                .satisfies(ex -> {
                    List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();
                    assertThat(revocationInfoList).hasSize(2);
                    Throwable fallbackError = (Throwable) revocationInfoList.get(1)
                        .ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_ERROR);
                    assertThat(fallbackError).hasMessageContaining("thisUpdate").hasMessageContaining("is too old");
                });
        }
    }

    private static CheckerBuilder checkerBuilder(OcspClient ocspClient) {
        return new CheckerBuilder(ocspClient);
    }

    /**
     * Builds a {@link ResilientOcspCertificateRevocationChecker} with, by default, a primary OCSP service
     * with two chained fallbacks: PRIMARY_URI -> FALLBACK_URI -> SECOND_FALLBACK_URI. The age limits are
     * per OCSP service, so they are stubbed on the mocked services and are relaxed by default.
     */
    private static final class CheckerBuilder {

        private final OcspClient ocspClient;
        private OcspServiceProvider ocspServiceProvider;
        private URI[] fallbackUris = {FALLBACK_URI, SECOND_FALLBACK_URI};
        private boolean primarySupportsNonce;
        private CircuitBreakerConfig circuitBreakerConfig = CircuitBreakerConfig.ofDefaults();
        private RetryConfig retryConfig;
        private Duration primaryMaxThisUpdateAge = LONG_THIS_UPDATE_AGE;
        private Duration fallbackMaxThisUpdateAge = LONG_THIS_UPDATE_AGE;

        private CheckerBuilder(OcspClient ocspClient) {
            this.ocspClient = ocspClient;
        }

        private CheckerBuilder withFallbacks(URI... fallbackUris) {
            this.fallbackUris = fallbackUris;
            return this;
        }

        private CheckerBuilder withoutFallbacks() {
            return withFallbacks();
        }

        private CheckerBuilder withPrimaryNonceSupport() {
            this.primarySupportsNonce = true;
            return this;
        }

        private CheckerBuilder withCircuitBreakerConfig(CircuitBreakerConfig circuitBreakerConfig) {
            this.circuitBreakerConfig = circuitBreakerConfig;
            return this;
        }

        private CheckerBuilder withRetryConfig(RetryConfig retryConfig) {
            this.retryConfig = retryConfig;
            return this;
        }

        private CheckerBuilder withOcspServiceProvider(OcspServiceProvider ocspServiceProvider) {
            this.ocspServiceProvider = ocspServiceProvider;
            return this;
        }

        private CheckerBuilder withPrimaryMaxThisUpdateAge(Duration primaryMaxThisUpdateAge) {
            this.primaryMaxThisUpdateAge = primaryMaxThisUpdateAge;
            return this;
        }

        private CheckerBuilder withFallbackMaxThisUpdateAge(Duration fallbackMaxThisUpdateAge) {
            this.fallbackMaxThisUpdateAge = fallbackMaxThisUpdateAge;
            return this;
        }

        private ResilientOcspCertificateRevocationChecker build() throws Exception {
            OcspServiceProvider serviceProvider = ocspServiceProvider != null ? ocspServiceProvider : buildMockServiceProvider();
            return new ResilientOcspCertificateRevocationChecker(
                ocspClient,
                serviceProvider,
                circuitBreakerConfig,
                retryConfig,
                OcspCertificateRevocationChecker.DEFAULT_TIME_SKEW
            );
        }

        private OcspServiceProvider buildMockServiceProvider() throws Exception {
            FallbackOcspService nextFallback = null;
            for (int i = fallbackUris.length - 1; i >= 0; i--) {
                FallbackOcspService fallbackService = mock(FallbackOcspService.class);
                when(fallbackService.getAccessLocation()).thenReturn(fallbackUris[i]);
                when(fallbackService.doesSupportNonce()).thenReturn(false);
                when(fallbackService.getNextFallback()).thenReturn(nextFallback);
                when(fallbackService.getMaxThisUpdateAge()).thenReturn(fallbackMaxThisUpdateAge);
                when(fallbackService.getMaxNextUpdateAge()).thenReturn(LONG_NEXT_UPDATE_AGE);
                nextFallback = fallbackService;
            }

            OcspService primaryService = mock(OcspService.class);
            when(primaryService.getAccessLocation()).thenReturn(PRIMARY_URI);
            when(primaryService.doesSupportNonce()).thenReturn(primarySupportsNonce);
            when(primaryService.getFallbackService()).thenReturn(Optional.ofNullable(nextFallback));
            when(primaryService.getMaxThisUpdateAge()).thenReturn(primaryMaxThisUpdateAge);
            when(primaryService.getMaxNextUpdateAge()).thenReturn(LONG_NEXT_UPDATE_AGE);

            OcspServiceProvider serviceProvider = mock(OcspServiceProvider.class);
            when(serviceProvider.getService(any(), any())).thenReturn(primaryService);
            return serviceProvider;
        }
    }

    private static MockedStatic<DateAndTime.DefaultClock> mockStaticClockAt(String isoDateTime) {
        MockedStatic<DateAndTime.DefaultClock> mockedClock = Mockito.mockStatic(DateAndTime.DefaultClock.class);
        mockDate(isoDateTime, mockedClock);
        return mockedClock;
    }

    // Overshooting the open-state duration is safe: the breaker transitions to HALF_OPEN lazily, when the
    // next call asks for permission, not on a timer.
    private static Duration waitLongerThan(Duration waitDurationInOpenState) {
        return waitDurationInOpenState.plusMillis(500);
    }

    private static CircuitBreakerStatistics getCircuitBreakerStatistics(RevocationInfo revocationInfo) {
        return (CircuitBreakerStatistics)
            revocationInfo.ocspResponseAttributes().get(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS);
    }

    private static CertificateStatus getCertificateStatus(RevocationInfo revocationInfo) throws Exception {
        OCSPResp ocspResp = (OCSPResp) revocationInfo.ocspResponseAttributes().get(RevocationInfo.KEY_OCSP_RESPONSE);
        final BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        final SingleResp certStatusResponse = basicResponse.getResponses()[0];
        return certStatusResponse.getCertStatus();
    }
}
