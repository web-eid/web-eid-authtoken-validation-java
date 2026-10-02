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
import eu.webeid.ocsp.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.ocsp.exceptions.UserCertificateOCSPException;
import eu.webeid.ocsp.exceptions.UserCertificateRevokedException;
import eu.webeid.ocsp.service.FallbackOcspService;
import eu.webeid.ocsp.service.OcspService;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateOCSPCheckFailedException;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateRevokedException;
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
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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

    public ResilientOcspCertificateRevocationChecker(OcspClient ocspClient,
                                                     OcspServiceProvider ocspServiceProvider,
                                                     CircuitBreakerConfig circuitBreakerConfig,
                                                     RetryConfig retryConfig,
                                                     Duration allowedOcspResponseTimeSkew) {
        super(ocspClient, ocspServiceProvider, allowedOcspResponseTimeSkew);
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
        OcspService primaryService = getOcspServiceProvider().getService(subjectCertificate, issuerCertificate);
        CertificateID certificateId = getCertificateId(subjectCertificate, issuerCertificate);

        Optional<FallbackOcspService> firstFallbackServiceOpt = primaryService.getFallbackService();
        if (firstFallbackServiceOpt.isEmpty()) {
            // Without a configured fallback, use the primary service directly without retry or circuit breaker.
            return List.of(request(primaryService, subjectCertificate, issuerCertificate, certificateId));
        }

        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(primaryService.getAccessLocation().toASCIIString());
        List<RevocationInfo> revocationInfoList = new ArrayList<>();
        // Requesting circuit breaker permission may change its state, for example from an expired OPEN
        // state to HALF_OPEN when automatic transition is disabled (the default). To report the state
        // that actually governs the request, the snapshot is captured inside the decorated call chain
        // rather than here.
        CircuitBreakerStatisticsSnapshot statisticsSnapshot = new CircuitBreakerStatisticsSnapshot(circuitBreaker);
        CheckedSupplier<RevocationInfo> fallbackSupplier = buildFallbackSupplier(firstFallbackServiceOpt.get(), subjectCertificate,
            issuerCertificate, certificateId, revocationInfoList);
        CheckedSupplier<RevocationInfo> decoratedSupplier = decorateWithResilience(primaryService, subjectCertificate,
            issuerCertificate, certificateId, revocationInfoList, fallbackSupplier, circuitBreaker, statisticsSnapshot);

        Try<RevocationInfo> result = Try.of(decoratedSupplier::get);
        RevocationInfo revocationInfo = processResult(result, subjectCertificate, revocationInfoList,
            statisticsSnapshot.get());
        revocationInfoList.add(revocationInfo);
        return revocationInfoList;
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
                                                                  CertificateID certificateId,
                                                                  List<RevocationInfo> revocationInfoList) {
        CheckedSupplier<RevocationInfo> firstFallbackSupplier = () -> {
            try {
                return request(firstFallbackService, subjectCertificate, issuerCertificate, certificateId);
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
                return request(secondFallbackService, subjectCertificate, issuerCertificate, certificateId);
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
                                                                  CertificateID certificateId,
                                                                   List<RevocationInfo> revocationInfoList,
                                                                   CheckedSupplier<RevocationInfo> fallbackSupplier,
                                                                   CircuitBreaker circuitBreaker,
                                                                   CircuitBreakerStatisticsSnapshot statisticsSnapshot) {
        CheckedSupplier<RevocationInfo> primarySupplier = () -> {
            // The circuit breaker has just permitted this call, so its current state is the one that
            // governs the request.
            statisticsSnapshot.capture();
            try {
                return request(primaryService, subjectCertificate, issuerCertificate, certificateId);
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
            .withFallback(List.of(ResilientUserCertificateOCSPCheckFailedException.class, CallNotPermittedException.class), e -> {
                // No-op if the primary request ran; otherwise the circuit breaker rejected the call and
                // this captures the rejecting state before the fallback request starts.
                statisticsSnapshot.capture();
                return fallbackSupplier.get();
            });

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

    private RevocationInfo request(OcspService ocspService, X509Certificate subjectCertificate, X509Certificate issuerCertificate, CertificateID certificateId) throws UserCertificateOCSPCheckFailedException, ResilientUserCertificateRevokedException, UserCertificateOCSPException {
        final URI ocspResponderUri = ocspService.getAccessLocation();
        final OCSPReq request = getOcspRequest(certificateId, ocspService);

        if (!ocspService.doesSupportNonce()) {
            LOG.debug("Disabling OCSP nonce extension");
        }


        OCSPResp response = null;
        Duration requestDuration = null;
        Instant responseTime = null;
        try {
            LOG.debug("Sending OCSP request");
            Instant requestTime = Instant.now();
            try {
                response = requireNonNull(getOcspClient().request(ocspResponderUri, request), "OCSPResp");
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

            if (!(response.getResponseObject() instanceof BasicOCSPResp basicResponse)) {
                throw createException("Missing or unsupported Basic OCSP Response", subjectCertificate,
                    ocspResponderUri, request, response, requestDuration, responseTime
                );
            }
            LOG.debug("OCSP response received successfully");

            verifyOcspResponse(basicResponse, ocspService, certificateId, issuerCertificate);
            if (ocspService.doesSupportNonce()) {
                checkNonce(request, basicResponse, ocspResponderUri);
            }
            LOG.debug("OCSP response verified successfully");

            return getRevocationInfo(ocspResponderUri, null, request, response, requestDuration, responseTime);
        } catch (ResilientUserCertificateOCSPCheckFailedException e) {
            throw e;
        } catch (UserCertificateRevokedException e) {
            // NOTE: unknown status does not throw UserCertificateRevokedException, it throws
            // UserCertificateOCSPCheckFailedException instead (see OcspResponseValidator.validateSubjectCertificateStatus),
            // so it falls through to the generic catch (Exception) block below, gets wrapped as
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
            // Users must not be able to modify this value.
            // Only ResilientUserCertificateOCSPCheckFailedException counts as a failure.
            // ResilientUserCertificateRevokedException is counted as a SUCCESS because it represents
            // a definitive OCSP answer (the service is healthy), not a transient failure.
            // Clear any recordExceptions list of the given configuration first, because it is combined
            // with the predicate below by OR and would otherwise widen what counts as a failure.
            .recordExceptions()
            .recordException(throwable -> throwable instanceof ResilientUserCertificateOCSPCheckFailedException)
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

    private final class CircuitBreakerStatisticsSnapshot {

        private final CircuitBreaker circuitBreaker;
        private CircuitBreakerStatistics statistics;

        private CircuitBreakerStatisticsSnapshot(CircuitBreaker circuitBreaker) {
            this.circuitBreaker = circuitBreaker;
        }

        private void capture() {
            if (statistics == null) {
                statistics = createCircuitBreakerStatistics(circuitBreaker);
            }
        }

        private CircuitBreakerStatistics get() {
            // Safety net: if neither the primary supplier nor the fallback ran, capture the statistics now.
            capture();
            return statistics;
        }
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
