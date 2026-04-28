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
import eu.webeid.ocsp.exceptions.UserCertificateRevokedException;
import eu.webeid.ocsp.protocol.OcspRequestBuilder;
import eu.webeid.ocsp.service.OcspService;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateOCSPCheckFailedException;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateRevokedException;
import eu.webeid.ocsp.service.FallbackOcspService;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.validator.ValidationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.core.functions.CheckedSupplier;
import io.github.resilience4j.decorators.Decorators;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import io.vavr.control.Try;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static eu.webeid.security.util.DateAndTime.requirePositiveDuration;
import static java.util.Objects.requireNonNull;

/**
 * OCSP revocation checker that falls back to configured fallback OCSP responders when the primary OCSP service fails.
 *
 * <p>Retry and circuit breaker handling are applied only when a fallback OCSP service is configured for the
 * certificate issuer. If no fallback is configured, validation is handled by the primary OCSP service directly.
 */
public class ResilientOcspCertificateRevocationChecker extends OcspCertificateRevocationChecker {

    private static final Logger LOG = LoggerFactory.getLogger(ResilientOcspCertificateRevocationChecker.class);

    private final CircuitBreakerRegistry circuitBreakerRegistry;
    private final RetryRegistry retryRegistry;
    private final boolean rejectUnknownOcspResponseStatus;
    private final Duration fallbackMaxOcspResponseThisUpdateAge;

    public ResilientOcspCertificateRevocationChecker(OcspClient ocspClient,
                                                     OcspServiceProvider ocspServiceProvider,
                                                     CircuitBreakerConfig circuitBreakerConfig,
                                                     RetryConfig retryConfig,
                                                     Duration allowedOcspResponseTimeSkew,
                                                     Duration primaryMaxOcspResponseThisUpdateAge,
                                                     Duration fallbackMaxOcspResponseThisUpdateAge,
                                                     boolean rejectUnknownOcspResponseStatus) {
        super(ocspClient, ocspServiceProvider, allowedOcspResponseTimeSkew, primaryMaxOcspResponseThisUpdateAge);
        this.fallbackMaxOcspResponseThisUpdateAge = requirePositiveDuration(fallbackMaxOcspResponseThisUpdateAge, "fallbackMaxOcspResponseThisUpdateAge");
        this.rejectUnknownOcspResponseStatus = rejectUnknownOcspResponseStatus;
        this.circuitBreakerRegistry = CircuitBreakerRegistry.custom()
            .withCircuitBreakerConfig(getCircuitBreakerConfig(circuitBreakerConfig))
            .build();
        this.retryRegistry = retryConfig != null ? RetryRegistry.custom()
            .withRetryConfig(getRetryConfig(retryConfig))
            .build() : null;
        if (LOG.isDebugEnabled()) {
            this.circuitBreakerRegistry.getEventPublisher()
                .onEntryAdded(entryAddedEvent -> {
                    CircuitBreaker circuitBreaker = entryAddedEvent.getAddedEntry();
                    LOG.debug("CircuitBreaker {} added", circuitBreaker.getName());
                    circuitBreaker.getEventPublisher()
                        .onEvent(event -> LOG.debug(event.toString()));
                });
        }
    }

    @Override
    public List<RevocationInfo> validateCertificateNotRevoked(X509Certificate subjectCertificate,
                                                              X509Certificate issuerCertificate) throws AuthTokenException {
        OcspService primaryService = resolvePrimaryOcspService(subjectCertificate);
        Optional<FallbackOcspService> firstFallbackServiceOpt = primaryService.getFallbackService();
        if (firstFallbackServiceOpt.isEmpty()) {
            // Without a configured fallback, use the primary service directly without retry or circuit breaker.
            return List.of(request(primaryService, subjectCertificate, issuerCertificate, getMaxOcspResponseThisUpdateAge()));
        }

        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(primaryService.getAccessLocation().toASCIIString());
        List<RevocationInfo> revocationInfoList = new ArrayList<>();
        CheckedSupplier<RevocationInfo> fallbackSupplier = buildFallbackSupplier(firstFallbackServiceOpt.get(), subjectCertificate,
            issuerCertificate, revocationInfoList);
        CheckedSupplier<RevocationInfo> decoratedSupplier = decorateWithResilience(primaryService, subjectCertificate,
            issuerCertificate, revocationInfoList, fallbackSupplier, circuitBreaker);

        // Take a snapshot of circuit breaker statistics right before the first request.
        CircuitBreakerStatistics circuitBreakerStatistics = createCircuitBreakerStatistics(circuitBreaker);
        RevocationInfo revocationInfo = processResult(Try.of(decoratedSupplier::get), subjectCertificate, revocationInfoList, circuitBreakerStatistics);
        revocationInfoList.add(revocationInfo);
        return revocationInfoList;
    }

    private OcspService resolvePrimaryOcspService(X509Certificate subjectCertificate) throws AuthTokenException {
        try {
            return getOcspServiceProvider().getService(subjectCertificate);
        } catch (CertificateException e) {
            throw new ResilientUserCertificateOCSPCheckFailedException(new ValidationInfo(subjectCertificate, List.of()));
        }
    }

    private CircuitBreakerStatistics createCircuitBreakerStatistics(CircuitBreaker circuitBreaker) {
        CircuitBreaker.Metrics metrics = circuitBreaker.getMetrics();
        return new CircuitBreakerStatistics(
            circuitBreaker.getState(),
            metrics.getFailureRate(),
            metrics.getSlowCallRate(),
            metrics.getNumberOfSlowCalls(),
            metrics.getNumberOfSlowSuccessfulCalls(),
            metrics.getNumberOfSlowFailedCalls(),
            metrics.getNumberOfBufferedCalls(),
            metrics.getNumberOfFailedCalls(),
            metrics.getNumberOfNotPermittedCalls(),
            metrics.getNumberOfSuccessfulCalls()
        );
    }

    private CheckedSupplier<RevocationInfo> buildFallbackSupplier(FallbackOcspService firstFallbackService,
                                                                  X509Certificate subjectCertificate,
                                                                  X509Certificate issuerCertificate,
                                                                  List<RevocationInfo> revocationInfoList) {
        CheckedSupplier<RevocationInfo> firstFallbackSupplier = () -> {
            try {
                return request(firstFallbackService, subjectCertificate, issuerCertificate, fallbackMaxOcspResponseThisUpdateAge);
            } catch (Exception e) {
                createAndAddRevocationInfoToList(e, revocationInfoList);
                throw e;
            }
        };
        // NOTE: Up to two fallbacks are currently supported. To enable the full potential of recursive fallbacks
        // with FallbackOcspService#getNextFallback, the fallback supplier creation needs to be changed.
        OcspService secondFallbackService = firstFallbackService.getNextFallback();
        if (secondFallbackService == null) {
            return firstFallbackSupplier;
        }
        CheckedSupplier<RevocationInfo> secondFallbackSupplier = () -> {
            try {
                return request(secondFallbackService, subjectCertificate, issuerCertificate, fallbackMaxOcspResponseThisUpdateAge);
            } catch (Exception e) {
                createAndAddRevocationInfoToList(e, revocationInfoList);
                throw e;
            }
        };
        return () -> {
            try {
                return firstFallbackSupplier.get();
            } catch (ResilientUserCertificateRevokedException e) {
                // NOTE: ResilientUserCertificateRevokedException must be re-thrown before the generic
                // catch (Exception) block. Without this, a "revoked" verdict from the first fallback would
                // be swallowed, and the second fallback could silently override it with a "good" response.
                throw e;
            } catch (Exception e) {
                return secondFallbackSupplier.get();
            }
        };
    }

    private CheckedSupplier<RevocationInfo> decorateWithResilience(OcspService primaryService,
                                                                   X509Certificate subjectCertificate,
                                                                   X509Certificate issuerCertificate,
                                                                   List<RevocationInfo> revocationInfoList,
                                                                   CheckedSupplier<RevocationInfo> fallbackSupplier,
                                                                   CircuitBreaker circuitBreaker) {
        CheckedSupplier<RevocationInfo> primarySupplier = () -> {
            try {
                return request(primaryService, subjectCertificate, issuerCertificate, getMaxOcspResponseThisUpdateAge());
            } catch (Exception e) {
                createAndAddRevocationInfoToList(e, revocationInfoList);
                throw e;
            }
        };
        Decorators.DecorateCheckedSupplier<RevocationInfo> decorateCheckedSupplier = Decorators.ofCheckedSupplier(primarySupplier);
        if (retryRegistry != null) {
            Retry retry = retryRegistry.retry(primaryService.getAccessLocation().toASCIIString());
            decorateCheckedSupplier.withRetry(retry);
        }
        decorateCheckedSupplier.withCircuitBreaker(circuitBreaker)
            .withFallback(List.of(ResilientUserCertificateOCSPCheckFailedException.class, CallNotPermittedException.class), e -> fallbackSupplier.get());

        return decorateCheckedSupplier.decorate();
    }

    private RevocationInfo processResult(Try<RevocationInfo> result, X509Certificate subjectCertificate,
                                         List<RevocationInfo> revocationInfoList,
                                         CircuitBreakerStatistics circuitBreakerStatistics) throws AuthTokenException {
        if (result.isSuccess()) {
            RevocationInfo revocationInfo = result.get();
            if (revocationInfoList.isEmpty()) {
                revocationInfo = withCircuitBreakerStatistics(revocationInfo, circuitBreakerStatistics);
            } else {
                addCircuitBreakerStatistics(revocationInfoList, circuitBreakerStatistics);
            }
            return revocationInfo;
        }
        addCircuitBreakerStatistics(revocationInfoList, circuitBreakerStatistics);
        Throwable throwable = result.getCause();
        if (throwable instanceof ResilientUserCertificateOCSPCheckFailedException exception) {
            exception.setValidationInfo(new ValidationInfo(subjectCertificate, revocationInfoList));
            throw exception;
        }
        if (throwable instanceof ResilientUserCertificateRevokedException exception) {
            exception.setValidationInfo(new ValidationInfo(subjectCertificate, revocationInfoList));
            throw exception;
        }
        throw new ResilientUserCertificateOCSPCheckFailedException(new ValidationInfo(subjectCertificate, revocationInfoList));
    }

    private void addCircuitBreakerStatistics(List<RevocationInfo> revocationInfoList,
                                             CircuitBreakerStatistics circuitBreakerStatistics) {
        revocationInfoList.set(0, withCircuitBreakerStatistics(revocationInfoList.get(0), circuitBreakerStatistics));
    }


    private void createAndAddRevocationInfoToList(Throwable throwable, List<RevocationInfo> revocationInfoList) {
        if (throwable instanceof ResilientUserCertificateOCSPCheckFailedException exception) {
            revocationInfoList.addAll((exception.getValidationInfo().revocationInfoList()));
            return;
        }
        if (throwable instanceof ResilientUserCertificateRevokedException exception) {
            revocationInfoList.addAll((exception.getValidationInfo().revocationInfoList()));
            return;
        }
        revocationInfoList.add(new RevocationInfo(null, new HashMap<>(Map.ofEntries(
            Map.entry(RevocationInfo.KEY_OCSP_ERROR, throwable)
        ))));
    }

    private RevocationInfo request(OcspService ocspService, X509Certificate subjectCertificate, X509Certificate issuerCertificate, Duration maxOcspResponseThisUpdateAge) throws ResilientUserCertificateOCSPCheckFailedException, ResilientUserCertificateRevokedException {
        URI ocspResponderUri = null;
        OCSPResp response = null;
        OCSPReq request = null;
        Duration requestDuration = null;
        Instant responseTime = null;
        try {
            ocspResponderUri = requireNonNull(ocspService.getAccessLocation(), "ocspResponderUri");

            final CertificateID certificateId = getCertificateId(subjectCertificate, issuerCertificate);
            request = new OcspRequestBuilder()
                .withCertificateId(certificateId)
                .enableOcspNonce(ocspService.doesSupportNonce())
                .build();

            if (!ocspService.doesSupportNonce()) {
                LOG.debug("Disabling OCSP nonce extension");
            }

            LOG.debug("Sending OCSP request");
            Instant requestTime = Instant.now();
            try {
                response = requireNonNull(getOcspClient().request(ocspResponderUri, request));
                responseTime = Instant.now();
                requestDuration = Duration.between(requestTime, responseTime);
            } catch (OCSPClientException e) {
                responseTime = Instant.now();
                requestDuration = Duration.between(requestTime, responseTime);
                RevocationInfo revocationInfo = getRevocationInfo(ocspResponderUri, e, request, null, requestDuration, responseTime);
                revocationInfo = withOCSPClientException(revocationInfo, e);
                throw new ResilientUserCertificateOCSPCheckFailedException(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
            }
            if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                throw createException("Response status: " + ocspStatusToString(response.getStatus()),
                    subjectCertificate, ocspResponderUri, request, response, requestDuration, responseTime
                );
            }

            final BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
            if (basicResponse == null) {
                throw createException("Missing Basic OCSP Response", subjectCertificate,
                    ocspResponderUri, request, response, requestDuration, responseTime
                );
            }
            LOG.debug("OCSP response received successfully");

            verifyOcspResponse(basicResponse, ocspService, certificateId, rejectUnknownOcspResponseStatus, maxOcspResponseThisUpdateAge);
            if (ocspService.doesSupportNonce()) {
                checkNonce(request, basicResponse, ocspResponderUri);
            }
            LOG.debug("OCSP response verified successfully");

            return getRevocationInfo(ocspResponderUri, null, request, response, requestDuration, responseTime);
        } catch (ResilientUserCertificateOCSPCheckFailedException e) {
            throw e;
        } catch (UserCertificateRevokedException e) {
            // NOTE: UserCertificateRevokedException covers both actual revocation and unknown status
            // when rejectUnknownOcspResponseStatus=false (see OcspResponseValidator.validateSubjectCertificateStatus).
            // When rejectUnknownOcspResponseStatus=true, unknown status throws UserCertificateUnknownException
            // instead, which falls through to the generic catch (Exception) block below, gets wrapped as
            // ResilientUserCertificateOCSPCheckFailedException, and triggers the circuit breaker fallback.
            // Here, wrapping as ResilientUserCertificateRevokedException ensures the circuit breaker ignores it
            // (a definitive OCSP answer, not a transient failure) and no fallback is attempted.
            RevocationInfo revocationInfo = getRevocationInfo(ocspResponderUri, e, request, response, requestDuration, responseTime);
            throw new ResilientUserCertificateRevokedException(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
        } catch (Exception e) {
            RevocationInfo revocationInfo = getRevocationInfo(ocspResponderUri, e, request, response, requestDuration, responseTime);
            throw new ResilientUserCertificateOCSPCheckFailedException(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
        }
    }


    private ResilientUserCertificateOCSPCheckFailedException createException(String message, X509Certificate subjectCertificate,
                                                                       URI ocspResponderUri, OCSPReq request, OCSPResp response,
                                                                       Duration requestDuration, Instant responseTime) throws ResilientUserCertificateOCSPCheckFailedException {
        ResilientUserCertificateOCSPCheckFailedException exception = new ResilientUserCertificateOCSPCheckFailedException(message);
        RevocationInfo revocationInfo = getRevocationInfo(ocspResponderUri, exception, request, response, requestDuration, responseTime);
        exception.setValidationInfo(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
        return exception;
    }

    private RevocationInfo getRevocationInfo(URI ocspResponderUri, Exception e, OCSPReq request, OCSPResp response,
                                             Duration requestDuration, Instant end) {
        Map<String, Object> ocspResponseAttributes = new HashMap<>();
        if (e != null) {
            ocspResponseAttributes.put(RevocationInfo.KEY_OCSP_ERROR, e);
        }
        if (request != null) {
            ocspResponseAttributes.put(RevocationInfo.KEY_OCSP_REQUEST, request);
        }
        if (response != null) {
            ocspResponseAttributes.put(RevocationInfo.KEY_OCSP_RESPONSE, response);
        }
        if (requestDuration != null) {
            ocspResponseAttributes.put(RevocationInfo.KEY_REQUEST_DURATION, requestDuration);
        }
        if (end != null) {
            ocspResponseAttributes.put(RevocationInfo.KEY_OCSP_RESPONSE_TIME, end);
        }
        return new RevocationInfo(ocspResponderUri, ocspResponseAttributes);
    }

    private static CircuitBreakerConfig getCircuitBreakerConfig(CircuitBreakerConfig circuitBreakerConfig) {
        return CircuitBreakerConfig.from(circuitBreakerConfig)
            // Users must not be able to modify these three values.
            .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
            .ignoreExceptions(ResilientUserCertificateRevokedException.class)
            .automaticTransitionFromOpenToHalfOpenEnabled(true)
            .build();
    }

    private static RetryConfig getRetryConfig(RetryConfig retryConfig) {
        return RetryConfig.from(retryConfig)
            // Users must not be able to modify this value.
            .ignoreExceptions(ResilientUserCertificateRevokedException.class)
            .build();
    }

    private static RevocationInfo withCircuitBreakerStatistics(RevocationInfo revocationInfo, CircuitBreakerStatistics circuitBreakerStatistics) {
        return revocationInfo.withAdditionalOcspResponseAttribute(RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS, circuitBreakerStatistics);
    }

    private static RevocationInfo withOCSPClientException(RevocationInfo revocationInfo, OCSPClientException e) {
        return revocationInfo
            .withAdditionalOcspResponseAttribute(RevocationInfo.KEY_OCSP_RESPONSE, e.getResponseBody())
            .withAdditionalOcspResponseAttribute(RevocationInfo.KEY_HTTP_STATUS_CODE, e.getStatusCode());
    }

    public record CircuitBreakerStatistics(
        CircuitBreaker.State state,
        float failureRate,
        float slowCallRate,
        int numberOfSlowCalls,
        int numberOfSlowSuccessfulCalls,
        int numberOfSlowFailedCalls,
        int numberOfBufferedCalls,
        int numberOfFailedCalls,
        long numberOfNotPermittedCalls,
        int numberOfSuccessfulCalls
    ) {}
}
