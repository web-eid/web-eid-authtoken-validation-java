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

package eu.webeid.security.validator.ocsp;

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.exceptions.UserCertificateRevokedException;
import eu.webeid.security.exceptions.UserCertificateUnknownException;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;
import eu.webeid.security.validator.ocsp.service.FallbackOcspServiceConfiguration;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.retry.RetryConfig;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2015CA;
import static eu.webeid.security.testutil.Certificates.getTestEsteid2018CA;
import static eu.webeid.security.testutil.Certificates.getTestSkOcspResponder2018;
import static eu.webeid.security.testutil.Certificates.getTestSkOcspResponder2020;
import static eu.webeid.security.testutil.DateMocker.mockDate;
import static eu.webeid.security.testutil.OcspServiceMaker.getAiaOcspServiceProvider;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ResilientOcspServiceTest {
    private static final URI PRIMARY_OCSP_URL = URI.create("http://aia.demo.sk.ee/esteid2018");
    private static final URI FALLBACK_OCSP_URL = URI.create("http://fallback.demo.sk.ee/ocsp");
    private static final Duration ALLOWED_TIME_SKEW = Duration.ofMinutes(15);
    private static final Duration MAX_THIS_UPDATE_AGE = Duration.ofMinutes(2);

    private X509Certificate subjectCertificate;
    private X509Certificate issuerCertificate;
    private byte[] validOcspResponseBytes;
    private byte[] revokedOcspResponseBytes;
    private byte[] unknownOcspResponseBytes;

    @BeforeAll
    static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    void setUp() throws Exception {
        subjectCertificate = getJaakKristjanEsteid2018Cert();
        issuerCertificate = getTestEsteid2018CA();
        validOcspResponseBytes = getSystemResource("ocsp_response.der");
        revokedOcspResponseBytes = getSystemResource("ocsp_response_revoked.der");
        unknownOcspResponseBytes = getSystemResource("ocsp_response_unknown.der");
    }

    @Test
    void whenFallbackConfigured_thenFallbackAndRecoverySucceeds() throws Exception {
        final OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_OCSP_URL), any()))
            .thenThrow(new IOException("Mocked exception 1"))
            .thenThrow(new IOException("Mocked exception 2"))
            .thenThrow(new IOException("Mocked exception 3"))
            .thenThrow(new IOException("Mocked exception 4"))
            .thenReturn(new OCSPResp(validOcspResponseBytes))
            .thenReturn(new OCSPResp(validOcspResponseBytes));
        when(ocspClient.request(eq(FALLBACK_OCSP_URL), any()))
            .thenReturn(new OCSPResp(validOcspResponseBytes));
        CircuitBreakerConfig circuitBreakerConfig = CircuitBreakerConfig.custom()
            .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
            .slidingWindowSize(4)
            .minimumNumberOfCalls(2)
            .failureRateThreshold(50)
            .permittedNumberOfCallsInHalfOpenState(2)
            .waitDurationInOpenState(Duration.ofMillis(100))  // Short wait for testing
            .automaticTransitionFromOpenToHalfOpenEnabled(true)
            .build();
        OcspServiceProvider ocspServiceProvider = createOcspServiceProviderWithFallback();
        ResilientOcspService resilientOcspService = new ResilientOcspService(
            ocspClient,
            ocspServiceProvider,
            circuitBreakerConfig,
            null,
            ALLOWED_TIME_SKEW,
            MAX_THIS_UPDATE_AGE,
            false
        );
        CircuitBreakerRegistry circuitBreakerRegistry = resilientOcspService.getCircuitBreakerRegistry();
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(PRIMARY_OCSP_URL.toASCIIString());
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-17T18:25:24", mockedClock);

            assertThatCode(() ->
                resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate)
            ).doesNotThrowAnyException();
            verify(ocspClient, times(1)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(1)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);

            assertThatCode(() ->
                resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate)
            ).doesNotThrowAnyException();
            verify(ocspClient, times(2)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(2)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.OPEN);

            assertThatCode(() ->
                resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate)
            ).doesNotThrowAnyException();
            verify(ocspClient, times(2)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(3)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.OPEN);

            await()
                .until(circuitBreaker::getState, equalTo(CircuitBreaker.State.HALF_OPEN));

            assertThatCode(() ->
                resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate)
            ).doesNotThrowAnyException();
            verify(ocspClient, times(3)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(4)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.HALF_OPEN);

            assertThatCode(() ->
                resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate)
            ).doesNotThrowAnyException();
            verify(ocspClient, times(4)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(5)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.OPEN);

            await()
                .until(circuitBreaker::getState, equalTo(CircuitBreaker.State.HALF_OPEN));

            assertThatCode(() ->
                resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate)
            ).doesNotThrowAnyException();
            verify(ocspClient, times(5)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(5)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.HALF_OPEN);

            assertThatCode(() ->
                resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate)
            ).doesNotThrowAnyException();
            verify(ocspClient, times(6)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(5)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);

            assertThatCode(() ->
                resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate)
            ).doesNotThrowAnyException();
            verify(ocspClient, times(7)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(5)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }
    }

    @Test
    void whenOcspResponseGood_thenNoFallbackAndSucceeds() throws Exception {
        final OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_OCSP_URL), any()))
            .thenReturn(new OCSPResp(validOcspResponseBytes));
        when(ocspClient.request(eq(FALLBACK_OCSP_URL), any()))
            .thenReturn(new OCSPResp(validOcspResponseBytes));
        OcspServiceProvider ocspServiceProvider = createOcspServiceProviderWithFallback();
        ResilientOcspService resilientOcspService = new ResilientOcspService(
            ocspClient,
            ocspServiceProvider,
            null,
            null,
            ALLOWED_TIME_SKEW,
            MAX_THIS_UPDATE_AGE,
            false
        );
        CircuitBreakerRegistry circuitBreakerRegistry = resilientOcspService.getCircuitBreakerRegistry();
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(PRIMARY_OCSP_URL.toASCIIString());
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-17T18:25:24", mockedClock);

            OcspValidationInfo validationInfo = resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate);
            assertThat(validationInfo).isNotNull();
            assertThat(validationInfo).extracting(OcspValidationInfo::getSubjectCertificate)
                .isEqualTo(subjectCertificate);
            assertThat(validationInfo).extracting(OcspValidationInfo::getOcspResponderUri)
                .isEqualTo(new URI("http://aia.demo.sk.ee/esteid2018"));
            assertThat(validationInfo).extracting(OcspValidationInfo::getOcspResponse)
                .isNotNull();

            verify(ocspClient, times(1)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(0)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }
    }

    @Test
    void whenRetryEnabledAndRetrySucceeds_thenNoFallbackAndSucceeds() throws Exception {
        final OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_OCSP_URL), any()))
            .thenThrow(new IOException("Mocked exception 1"))
            .thenThrow(new IOException("Mocked exception 2"))
            .thenReturn(new OCSPResp(validOcspResponseBytes));
        when(ocspClient.request(eq(FALLBACK_OCSP_URL), any()))
            .thenReturn(new OCSPResp(validOcspResponseBytes));
        OcspServiceProvider ocspServiceProvider = createOcspServiceProviderWithFallback();
        ResilientOcspService resilientOcspService = new ResilientOcspService(
            ocspClient,
            ocspServiceProvider,
            null,
            RetryConfig.ofDefaults(), // Retry enabled
            ALLOWED_TIME_SKEW,
            MAX_THIS_UPDATE_AGE,
            false
        );
        CircuitBreakerRegistry circuitBreakerRegistry = resilientOcspService.getCircuitBreakerRegistry();
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(PRIMARY_OCSP_URL.toASCIIString());
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-17T18:25:24", mockedClock);

            OcspValidationInfo validationInfo = resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate);
            assertThat(validationInfo).isNotNull();
            assertThat(validationInfo).extracting(OcspValidationInfo::getSubjectCertificate)
                .isEqualTo(subjectCertificate);
            assertThat(validationInfo).extracting(OcspValidationInfo::getOcspResponderUri)
                .isEqualTo(new URI("http://aia.demo.sk.ee/esteid2018"));
            assertThat(validationInfo).extracting(OcspValidationInfo::getOcspResponse)
                .isNotNull();

            verify(ocspClient, times(3)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(0)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }
    }

    @Test
    void whenOcspResponseRevoked_thenNoFallbackAndThrows() throws Exception {
        final OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_OCSP_URL), any()))
            .thenReturn(new OCSPResp(revokedOcspResponseBytes));
        when(ocspClient.request(eq(FALLBACK_OCSP_URL), any()))
            .thenReturn(new OCSPResp(validOcspResponseBytes));
        OcspServiceProvider ocspServiceProvider = createOcspServiceProviderWithFallback();
        ResilientOcspService resilientOcspService = new ResilientOcspService(
            ocspClient,
            ocspServiceProvider,
            null,
            null,
            ALLOWED_TIME_SKEW,
            MAX_THIS_UPDATE_AGE,
            false
        );
        CircuitBreakerRegistry circuitBreakerRegistry = resilientOcspService.getCircuitBreakerRegistry();
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(PRIMARY_OCSP_URL.toASCIIString());
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-18T00:00:00", mockedClock);

            assertThatExceptionOfType(UserCertificateRevokedException.class)
                .isThrownBy(() ->
                    resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate))
                .withMessage("User certificate has been revoked: Revocation reason: 0")
                .satisfies(e -> assertThat(e.getOcspValidationInfo()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getSubjectCertificate()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponderUri()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponderUri().toASCIIString()).isEqualTo("http://aia.demo.sk.ee/esteid2018"))
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponse()).isNotNull());

            verify(ocspClient, times(1)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(0)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }
    }

    @Test
    void whenOcspResponseUnknown_thenNoFallbackAndThrows() throws Exception {
        final OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_OCSP_URL), any()))
            .thenReturn(new OCSPResp(unknownOcspResponseBytes));
        when(ocspClient.request(eq(FALLBACK_OCSP_URL), any()))
            .thenReturn(new OCSPResp(validOcspResponseBytes));
        OcspServiceProvider ocspServiceProvider = createOcspServiceProviderWithFallback();
        ResilientOcspService resilientOcspService = new ResilientOcspService(
            ocspClient,
            ocspServiceProvider,
            null,
            null,
            ALLOWED_TIME_SKEW,
            MAX_THIS_UPDATE_AGE,
            false
        );
        CircuitBreakerRegistry circuitBreakerRegistry = resilientOcspService.getCircuitBreakerRegistry();
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(PRIMARY_OCSP_URL.toASCIIString());
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-18T00:16:25", mockedClock);

            assertThatExceptionOfType(UserCertificateRevokedException.class)
                .isThrownBy(() ->
                    resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate))
                .withMessage("User certificate has been revoked: Unknown status")
                .satisfies(e -> assertThat(e.getOcspValidationInfo()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getSubjectCertificate()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponderUri()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponderUri().toASCIIString()).isEqualTo("http://aia.demo.sk.ee/esteid2018"))
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponse()).isNotNull());

            verify(ocspClient, times(1)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(0)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }
    }

    @Test
    void whenPrimaryOcspResponseUnknownAndRejectUnknownOcspResponseStatusConfiguration_thenFallbackAndSucceeds() throws Exception {
        final OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_OCSP_URL), any()))
            .thenReturn(new OCSPResp(unknownOcspResponseBytes));
        when(ocspClient.request(eq(FALLBACK_OCSP_URL), any()))
            .thenReturn(new OCSPResp(validOcspResponseBytes));
        OcspServiceProvider ocspServiceProvider = createOcspServiceProviderWithFallback();
        ResilientOcspService resilientOcspService = new ResilientOcspService(
            ocspClient,
            ocspServiceProvider,
            null,
            null,
            ALLOWED_TIME_SKEW,
            MAX_THIS_UPDATE_AGE,
            true // rejectUnknownOcspResponseStatus
        );
        CircuitBreakerRegistry circuitBreakerRegistry = resilientOcspService.getCircuitBreakerRegistry();
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(PRIMARY_OCSP_URL.toASCIIString());
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-17T18:25:24", mockedClock);

            OcspValidationInfo validationInfo = resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate);
            assertThat(validationInfo).isNotNull();
            assertThat(validationInfo).extracting(OcspValidationInfo::getSubjectCertificate)
                .isEqualTo(subjectCertificate);
            assertThat(validationInfo).extracting(OcspValidationInfo::getOcspResponderUri)
                .isEqualTo(new URI("http://fallback.demo.sk.ee/ocsp"));
            assertThat(validationInfo).extracting(OcspValidationInfo::getOcspResponse)
                .isNotNull();

            verify(ocspClient, times(1)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(1)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }
    }

    @Test
    void whenPrimaryAndFallbackRevocationStatusUnknownAndRejectUnknownOcspResponseStatusConfiguration_thenThrows() throws Exception {
        final OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_OCSP_URL), any()))
            .thenReturn(new OCSPResp(unknownOcspResponseBytes));
        when(ocspClient.request(eq(FALLBACK_OCSP_URL), any()))
            .thenReturn(new OCSPResp(unknownOcspResponseBytes));
        FallbackOcspServiceConfiguration fallbackConfig = new FallbackOcspServiceConfiguration(
            PRIMARY_OCSP_URL,
            FALLBACK_OCSP_URL,
            getTestSkOcspResponder2020(),
            false
        );
        OcspServiceProvider ocspServiceProvider = createOcspServiceProviderWithFallback(fallbackConfig);
        ResilientOcspService resilientOcspService = new ResilientOcspService(
            ocspClient,
            ocspServiceProvider,
            null,
            null,
            ALLOWED_TIME_SKEW,
            MAX_THIS_UPDATE_AGE,
            true // rejectUnknownOcspResponseStatus
        );
        CircuitBreakerRegistry circuitBreakerRegistry = resilientOcspService.getCircuitBreakerRegistry();
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(PRIMARY_OCSP_URL.toASCIIString());
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-18T00:16:25", mockedClock);

            assertThatExceptionOfType(UserCertificateUnknownException.class)
                .isThrownBy(() ->
                    resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate))
                .withMessage("Unknown status")
                .satisfies(e -> assertThat(e.getOcspValidationInfo()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getSubjectCertificate()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponderUri()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponderUri().toASCIIString()).isEqualTo("http://fallback.demo.sk.ee/ocsp"))
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponse()).isNotNull());


            verify(ocspClient, times(1)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(1)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }
    }

    @Test
    void whenPrimaryAndFallbackConnectionFail_thenThrows() throws Exception {
        final OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_OCSP_URL), any()))
            .thenThrow(new IOException("Mocked exception 1"));
        when(ocspClient.request(eq(FALLBACK_OCSP_URL), any()))
            .thenThrow(new IOException("Mocked exception 2"));
        OcspServiceProvider ocspServiceProvider = createOcspServiceProviderWithFallback();
        ResilientOcspService resilientOcspService = new ResilientOcspService(
            ocspClient,
            ocspServiceProvider,
            null,
            null,
            ALLOWED_TIME_SKEW,
            MAX_THIS_UPDATE_AGE,
            false
        );
        CircuitBreakerRegistry circuitBreakerRegistry = resilientOcspService.getCircuitBreakerRegistry();
        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(PRIMARY_OCSP_URL.toASCIIString());
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-18T00:16:25", mockedClock);

            assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
                .isThrownBy(() ->
                    resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate))
                .withMessage("User certificate revocation check has failed")
                .withCause(new IOException("Mocked exception 2"))
                .satisfies(e -> assertThat(e.getOcspValidationInfo()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getSubjectCertificate()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponse()).isNull());

            verify(ocspClient, times(1)).request(eq(PRIMARY_OCSP_URL), any());
            verify(ocspClient, times(1)).request(eq(FALLBACK_OCSP_URL), any());
            assertThat(circuitBreaker.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        }
    }

    @Test
    void whenNoFallbackConfigured_thenPrimaryFailureThrows() throws Exception {
        final OcspClient ocspClient = mock(OcspClient.class);
        when(ocspClient.request(eq(PRIMARY_OCSP_URL), any()))
            .thenThrow(new IOException("Mocked exception"));
        OcspServiceProvider ocspServiceProvider = getAiaOcspServiceProvider();
        ResilientOcspService resilientOcspService = new ResilientOcspService(
            ocspClient,
            ocspServiceProvider,
            null,
            null,
            ALLOWED_TIME_SKEW,
            MAX_THIS_UPDATE_AGE,
            false
        );
        try (var mockedClock = mockStatic(DateAndTime.DefaultClock.class)) {
            mockDate("2021-09-17T18:25:24", mockedClock);

            assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
                .isThrownBy(() ->
                    resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate))
                .withMessage("User certificate revocation check has failed")
                .withCause(new IOException("Mocked exception"))
                .satisfies(e -> assertThat(e.getOcspValidationInfo()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getSubjectCertificate()).isNotNull())
                .satisfies(e -> assertThat(e.getOcspValidationInfo().getOcspResponse()).isNull());
        }
    }

    private OcspServiceProvider createOcspServiceProviderWithFallback() throws Exception {
        FallbackOcspServiceConfiguration fallbackConfig = new FallbackOcspServiceConfiguration(
            PRIMARY_OCSP_URL,
            FALLBACK_OCSP_URL,
            getTestSkOcspResponder2018(),
            false
        );
        return createOcspServiceProviderWithFallback(fallbackConfig);
    }

    private OcspServiceProvider createOcspServiceProviderWithFallback(FallbackOcspServiceConfiguration fallbackConfig) throws Exception {
        List<X509Certificate> trustedCACertificates = Arrays.asList(
            getTestEsteid2018CA(),
            getTestSkOcspResponder2020(),
            getTestEsteid2015CA()
        );
        AiaOcspServiceConfiguration aiaConfig =
            new AiaOcspServiceConfiguration(
                Set.of(PRIMARY_OCSP_URL),
                CertificateValidator.buildTrustAnchorsFromCertificates(trustedCACertificates),
                CertificateValidator.buildCertStoreFromCertificates(trustedCACertificates)
            );
        return new OcspServiceProvider(
            null,
            aiaConfig,
            Collections.singletonList(fallbackConfig)
        );
    }

    private static byte[] getSystemResource(String name) throws IOException {
        try (InputStream resourceAsStream = ClassLoader.getSystemResourceAsStream(name)) {
            if (resourceAsStream == null) {
                throw new IOException("Resource not found: " + name);
            }
            return resourceAsStream.readAllBytes();
        }
    }
}
