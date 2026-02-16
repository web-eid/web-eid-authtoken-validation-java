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
import eu.webeid.ocsp.service.OcspService;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateOCSPCheckFailedException;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateRevokedException;
import eu.webeid.ocsp.service.FallbackOcspService;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.retry.RetryConfig;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static eu.webeid.ocsp.OcspCertificateRevocationCheckerTest.getOcspResponseBytesFromResources;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_AUTH_TOKEN;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_CHALLENGE_NONCE;
import static eu.webeid.security.testutil.AuthTokenValidators.getDefaultAuthTokenValidatorBuilder;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ResilientOcspCertificateRevocationCheckerTest {

    private static final URI PRIMARY_URI = URI.create("http://primary.ocsp.test");
    private static final URI FALLBACK_URI = URI.create("http://fallback.ocsp.test");
    private static final URI SECOND_FALLBACK_URI = URI.create("http://second-fallback.ocsp.test");

    private X509Certificate estEid2018Cert;
    private X509Certificate testEsteid2018CA;
    private OCSPResp ocspRespGood;

    @BeforeEach
    void setUp() throws Exception {
        estEid2018Cert = getJaakKristjanEsteid2018Cert();
        testEsteid2018CA = getTestEsteid2018CA();
        ocspRespGood = new OCSPResp(getOcspResponseBytesFromResources("ocsp_response.der"));
    }

    // TODO Rename to match the expected result
    @Test
    void whenMultipleValidationCalls_thenStaleListenersMutatePreviousResults() throws Exception {
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
        ResilientOcspCertificateRevocationChecker resilientChecker = buildChecker(ocspClient, null, false);
        AuthTokenValidator validator = getDefaultAuthTokenValidatorBuilder()
            .withCertificateRevocationChecker(resilientChecker)
            .build();
        WebEidAuthToken authToken = validator.parse(VALID_AUTH_TOKEN);

        ResilientUserCertificateOCSPCheckFailedException ex1 = assertThrows(ResilientUserCertificateOCSPCheckFailedException.class,
            () -> validator.validate(authToken, VALID_CHALLENGE_NONCE));
        List<RevocationInfo> revocationInfo1 = ex1.getValidationInfo().revocationInfoList();
        assertThat(revocationInfo1).hasSize(3);
        assertThat(revocationInfo1)
            .extracting(ri -> ((OCSPClientException) ri.ocspResponseAttributes().get("OCSP_ERROR")).getMessage())
            .containsExactly(
                "Primary OCSP service unavailable (call1)",
                "Fallback OCSP service unavailable (call1)",
                "Secondary fallback OCSP service unavailable (call1)"
            );
        ResilientUserCertificateOCSPCheckFailedException ex2 = assertThrows(ResilientUserCertificateOCSPCheckFailedException.class,
            () -> validator.validate(authToken, VALID_CHALLENGE_NONCE));
        List<RevocationInfo> revocationInfo2 = ex2.getValidationInfo().revocationInfoList();
        assertThat(revocationInfo2).hasSize(3);
        assertThat(revocationInfo2)
            .extracting(ri -> ((OCSPClientException) ri.ocspResponseAttributes().get("OCSP_ERROR")).getMessage())
            .containsExactly(
                "Primary OCSP service unavailable (call2)",
                "Fallback OCSP service unavailable (call2)",
                "Secondary fallback OCSP service unavailable (call2)"
            );
        assertThat(revocationInfo1).hasSize(3);
        assertThat(revocationInfo1)
            .extracting(ri -> ((OCSPClientException) ri.ocspResponseAttributes().get("OCSP_ERROR")).getMessage())
            .containsExactly(
                "Primary OCSP service unavailable (call1)",
                "Fallback OCSP service unavailable (call1)",
                "Secondary fallback OCSP service unavailable (call1)"
            );
    }

    @Test
    void whenFirstFallbackReturnsRevoked_thenRevocationPropagatesWithoutSecondFallback() throws Exception {
        OCSPResp ocspRespRevoked = new OCSPResp(getOcspResponseBytesFromResources("ocsp_response_revoked.der"));

        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException("Primary OCSP service unavailable"));
        when(ocspClient.request(eq(FALLBACK_URI), any()))
            .thenReturn(ocspRespRevoked);
        when(ocspClient.request(eq(SECOND_FALLBACK_URI), any()))
            .thenReturn(ocspRespGood);

        ResilientOcspCertificateRevocationChecker checker = buildChecker(ocspClient, null, false);

        assertThatExceptionOfType(ResilientUserCertificateRevokedException.class)
            .isThrownBy(() -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA))
            .withMessage("User certificate has been revoked");

        verify(ocspClient, never()).request(eq(SECOND_FALLBACK_URI), any());
    }

    @Test
    void whenMaxAttemptsIsTwoAndAllCallsFail_thenRevocationInfoListShouldHaveFourElements() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException());
        when(ocspClient.request(eq(FALLBACK_URI), any()))
            .thenThrow(new OCSPClientException());
        when(ocspClient.request(eq(SECOND_FALLBACK_URI), any()))
            .thenThrow(new OCSPClientException());

        RetryConfig retryConfig = RetryConfig.custom()
            .maxAttempts(2)
            .build();

        ResilientOcspCertificateRevocationChecker checker = buildChecker(ocspClient, retryConfig, false);
        ResilientUserCertificateOCSPCheckFailedException ex = assertThrows(ResilientUserCertificateOCSPCheckFailedException.class, () -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA));
        assertThat(ex.getValidationInfo().revocationInfoList().size()).isEqualTo(4);
    }

    @Test
    @Disabled("Primary supplier has allowThisUpdateInPast disabled and that is checked before revocation, " +
        "which results in ResilientUserCertificateOCSPCheckFailedException")
    void whenMaxAttemptsIsTwoAndFirstCallFails_thenTwoCallsToPrimaryShouldBeRecorded() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenThrow(new OCSPClientException("Primary OCSP service unavailable (call1)"))
            .thenReturn(ocspRespGood);

        RetryConfig retryConfig = RetryConfig.custom()
            .maxAttempts(2)
            .build();

        ResilientOcspCertificateRevocationChecker checker = buildChecker(ocspClient, retryConfig, false);
        List<RevocationInfo> revocationInfoList = checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        assertThat(revocationInfoList.size()).isEqualTo(2);

        Map<String, Object> firstResponseAttributes = revocationInfoList.get(0).ocspResponseAttributes();
        OCSPClientException ex1 = (OCSPClientException) firstResponseAttributes.get("OCSP_ERROR");
        assertThat(ex1.getMessage()).isEqualTo("Primary OCSP service unavailable (call1)");

        Map<String, Object> secondResponseAttributes = revocationInfoList.get(1).ocspResponseAttributes();
        OCSPResp ocspResp = (OCSPResp) secondResponseAttributes.get("OCSP_RESPONSE");
        final BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        final SingleResp certStatusResponse = basicResponse.getResponses()[0];
        assertThat(certStatusResponse.getCertStatus()).isEqualTo(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);
    }

    @Test
    @Disabled("Primary supplier has allowThisUpdateInPast disabled and that is checked before revocation, " +
        "which results in ResilientUserCertificateOCSPCheckFailedException")
    void whenFirstCallSucceeds_thenRevocationInfoListShouldHaveOneElementAndItShouldHaveGoodStatus() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenReturn(ocspRespGood);

        ResilientOcspCertificateRevocationChecker checker = buildChecker(ocspClient, null, false);

        List<RevocationInfo> revocationInfoList = checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA);
        assertThat(revocationInfoList.size()).isEqualTo(1);
        Map<String, Object> responseAttributes = revocationInfoList.get(0).ocspResponseAttributes();
        OCSPResp ocspResp = (OCSPResp) responseAttributes.get("OCSP_RESPONSE");
        final BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        final SingleResp certStatusResponse = basicResponse.getResponses()[0];
        assertThat(certStatusResponse.getCertStatus()).isEqualTo(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);
    }

    @Test
    @Disabled("Primary supplier has allowThisUpdateInPast disabled and that is checked before revocation, " +
        "which results in ResilientUserCertificateOCSPCheckFailedException")
    void whenFirstCallResultsInRevoked_thenRevocationInfoListShouldHaveOneElementAndItShouldHaveRevokedStatus() throws Exception {
        OcspClient ocspClient = mock(OcspClient.class);
        OCSPResp ocspRespRevoked = new OCSPResp(getOcspResponseBytesFromResources("ocsp_response_revoked.der"));
        when(ocspClient.request(eq(PRIMARY_URI), any()))
            .thenReturn(ocspRespRevoked);

        ResilientOcspCertificateRevocationChecker checker = buildChecker(ocspClient, null, false);
        ResilientUserCertificateRevokedException ex = assertThrows(ResilientUserCertificateRevokedException.class, () -> checker.validateCertificateNotRevoked(estEid2018Cert, testEsteid2018CA));
        List<RevocationInfo> revocationInfoList = ex.getValidationInfo().revocationInfoList();
        assertThat(revocationInfoList.size()).isEqualTo(1);
        Map<String, Object> responseAttributes = ex.getValidationInfo().revocationInfoList().get(0).ocspResponseAttributes();
        OCSPResp ocspResp = (OCSPResp) responseAttributes.get("OCSP_RESPONSE");
        final BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        final SingleResp certStatusResponse = basicResponse.getResponses()[0];
        assertThat(certStatusResponse.getCertStatus()).isInstanceOf(RevokedStatus.class);
    }

    private ResilientOcspCertificateRevocationChecker buildChecker(OcspClient ocspClient, RetryConfig retryConfig, boolean rejectUnknownOcspResponseStatus) throws Exception {
        FallbackOcspService secondFallbackService = mock(FallbackOcspService.class);
        when(secondFallbackService.getAccessLocation()).thenReturn(SECOND_FALLBACK_URI);
        when(secondFallbackService.doesSupportNonce()).thenReturn(false);

        FallbackOcspService fallbackService = mock(FallbackOcspService.class);
        when(fallbackService.getAccessLocation()).thenReturn(FALLBACK_URI);
        when(fallbackService.doesSupportNonce()).thenReturn(false);
        when(fallbackService.getNextFallback()).thenReturn(secondFallbackService);

        OcspService primaryService = mock(OcspService.class);
        when(primaryService.getAccessLocation()).thenReturn(PRIMARY_URI);
        when(primaryService.doesSupportNonce()).thenReturn(false);
        when(primaryService.getFallbackService()).thenReturn(fallbackService);

        OcspServiceProvider ocspServiceProvider = mock(OcspServiceProvider.class);
        when(ocspServiceProvider.getService(any())).thenReturn(primaryService);

        return new ResilientOcspCertificateRevocationChecker(
            ocspClient,
            ocspServiceProvider,
            CircuitBreakerConfig.ofDefaults(),
            retryConfig,
            OcspCertificateRevocationChecker.DEFAULT_TIME_SKEW,
            OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE,
            rejectUnknownOcspResponseStatus
        );
    }
}
