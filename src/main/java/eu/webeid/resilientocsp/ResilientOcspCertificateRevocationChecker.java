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
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.validator.ValidationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.decorators.Decorators;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import io.vavr.CheckedFunction0;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public class ResilientOcspCertificateRevocationChecker extends OcspCertificateRevocationChecker {

    private static final Logger LOG = LoggerFactory.getLogger(ResilientOcspCertificateRevocationChecker.class);

    private final CircuitBreakerRegistry circuitBreakerRegistry;
    private final RetryRegistry retryRegistry;
    private final boolean rejectUnknownOcspResponseStatus;

    public ResilientOcspCertificateRevocationChecker(OcspClient ocspClient,
                                                     OcspServiceProvider ocspServiceProvider,
                                                     CircuitBreakerConfig circuitBreakerConfig,
                                                     RetryConfig retryConfig,
                                                     Duration allowedOcspResponseTimeSkew,
                                                     Duration maxOcspResponseThisUpdateAge,
                                                     boolean rejectUnknownOcspResponseStatus) {
        super(ocspClient, ocspServiceProvider, allowedOcspResponseTimeSkew, maxOcspResponseThisUpdateAge);
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
        OcspService ocspService;
        try {
            ocspService = getOcspServiceProvider().getService(subjectCertificate);
        } catch (CertificateException e) {
            throw new ResilientUserCertificateOCSPCheckFailedException(new ValidationInfo(subjectCertificate, List.of()));
        }
        final OcspService fallbackOcspService = ocspService.getFallbackService();
        if (fallbackOcspService == null) {
            return List.of(request(ocspService, subjectCertificate, issuerCertificate, false));
        }

        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(ocspService.getAccessLocation().toASCIIString());

        List<RevocationInfo> revocationInfoList = new ArrayList<>();

        CheckedFunction0<RevocationInfo> primarySupplier = () -> request(ocspService, subjectCertificate, issuerCertificate, false);
        OcspService firstFallbackService = ocspService.getFallbackService();
        CheckedFunction0<RevocationInfo> firstFallbackSupplier = () -> request(firstFallbackService, subjectCertificate, issuerCertificate, true);
        OcspService secondFallbackService = getOcspServiceProvider().getFallbackService(firstFallbackService.getAccessLocation());
        CheckedFunction0<RevocationInfo> fallbackSupplier;
        if (secondFallbackService == null) {
            fallbackSupplier = firstFallbackSupplier;
        } else {
            CheckedFunction0<RevocationInfo> secondFallbackSupplier = () -> request(secondFallbackService, subjectCertificate, issuerCertificate, true);
            fallbackSupplier = () -> {
                try {
                    return firstFallbackSupplier.apply();
                } catch (ResilientUserCertificateRevokedException e) {
                    // NOTE: ResilientUserCertificateRevokedException must be re-thrown before the generic
                    // catch (Exception) block. Without this, a "revoked" verdict from the first fallback would
                    // be swallowed, and the second fallback could silently override it with a "good" response.
                    throw e;
                } catch (Exception e) {
                    if (e instanceof ResilientUserCertificateOCSPCheckFailedException exception) {
                        revocationInfoList.addAll((exception.getValidationInfo().revocationInfoList()));
                    } else {
                        revocationInfoList.add(new RevocationInfo(null, Map.ofEntries(
                            Map.entry(RevocationInfo.KEY_OCSP_ERROR, e)
                        )));
                    }
                    return secondFallbackSupplier.apply();
                }
            };
        }
        Decorators.DecorateCheckedSupplier<RevocationInfo> decorateCheckedSupplier = Decorators.ofCheckedSupplier(primarySupplier);
        if (retryRegistry != null) {
            Retry retry = retryRegistry.retry(ocspService.getAccessLocation().toASCIIString());
            retry.getEventPublisher().onError(event -> {
                Throwable throwable = event.getLastThrowable();
                if (throwable == null) {
                    return;
                }
                createAndAddRevocationInfoToList(throwable, revocationInfoList);
            });
            decorateCheckedSupplier.withRetry(retry);
        }
        decorateCheckedSupplier.withCircuitBreaker(circuitBreaker)
            .withFallback(List.of(ResilientUserCertificateOCSPCheckFailedException.class, CallNotPermittedException.class), e -> {
                createAndAddRevocationInfoToList(e, revocationInfoList);
                return fallbackSupplier.apply();
            });

        CheckedFunction0<RevocationInfo> decoratedSupplier = decorateCheckedSupplier.decorate();

        Try<RevocationInfo> result = Try.of(decoratedSupplier);

        RevocationInfo revocationInfo = result.getOrElseThrow(throwable -> {
            if (throwable instanceof ResilientUserCertificateOCSPCheckFailedException exception) {
                revocationInfoList.addAll(exception.getValidationInfo().revocationInfoList());
                exception.setValidationInfo(new ValidationInfo(subjectCertificate, revocationInfoList));
                return exception;
            }
            if (throwable instanceof ResilientUserCertificateRevokedException exception) {
                revocationInfoList.addAll(exception.getValidationInfo().revocationInfoList());
                exception.setValidationInfo(new ValidationInfo(subjectCertificate, revocationInfoList));
                return exception;
            }
            // TODO This should always be TaraUserCertificateOCSPCheckFailedException when reached?
            return new ResilientUserCertificateOCSPCheckFailedException(new ValidationInfo(subjectCertificate, revocationInfoList));
        });

        revocationInfoList.add(revocationInfo);
        return revocationInfoList;
    }

    private void createAndAddRevocationInfoToList(Throwable throwable, List<RevocationInfo> revocationInfoList) {
        if (throwable instanceof ResilientUserCertificateOCSPCheckFailedException exception) {
            revocationInfoList.addAll((exception.getValidationInfo().revocationInfoList()));
            return;
        }
        revocationInfoList.add(new RevocationInfo(null, Map.ofEntries(
            Map.entry(RevocationInfo.KEY_OCSP_ERROR, throwable)
        )));
    }

    private RevocationInfo request(OcspService ocspService, X509Certificate subjectCertificate, X509Certificate issuerCertificate, boolean allowThisUpdateInPast) throws ResilientUserCertificateOCSPCheckFailedException, ResilientUserCertificateRevokedException {
        URI ocspResponderUri = null;
        OCSPResp response = null;
        OCSPReq request = null;
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
            response = requireNonNull(getOcspClient().request(ocspResponderUri, request)); // TODO: This should trigger fallback?
            if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                ResilientUserCertificateOCSPCheckFailedException exception = new ResilientUserCertificateOCSPCheckFailedException("Response status: " + ocspStatusToString(response.getStatus()));
                RevocationInfo revocationInfo = new RevocationInfo(ocspService.getAccessLocation(), Map.ofEntries(
                    Map.entry(RevocationInfo.KEY_OCSP_ERROR, exception),
                    Map.entry(RevocationInfo.KEY_OCSP_REQUEST, request),
                    Map.entry(RevocationInfo.KEY_OCSP_RESPONSE, response)
                ));
                exception.setValidationInfo(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
                throw exception;
            }

            final BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
            if (basicResponse == null) {
                ResilientUserCertificateOCSPCheckFailedException exception = new ResilientUserCertificateOCSPCheckFailedException("Missing Basic OCSP Response");
                RevocationInfo revocationInfo = new RevocationInfo(ocspService.getAccessLocation(), Map.ofEntries(
                    Map.entry(RevocationInfo.KEY_OCSP_ERROR, exception),
                    Map.entry(RevocationInfo.KEY_OCSP_REQUEST, request),
                    Map.entry(RevocationInfo.KEY_OCSP_RESPONSE, response)
                ));
                exception.setValidationInfo(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
                throw exception;
            }
            LOG.debug("OCSP response received successfully");

            verifyOcspResponse(basicResponse, ocspService, certificateId, rejectUnknownOcspResponseStatus, allowThisUpdateInPast);
            if (ocspService.doesSupportNonce()) {
                checkNonce(request, basicResponse, ocspResponderUri);
            }
            LOG.debug("OCSP response verified successfully");

            return new RevocationInfo(ocspResponderUri, Map.ofEntries(
                Map.entry(RevocationInfo.KEY_OCSP_REQUEST, request),
                Map.entry(RevocationInfo.KEY_OCSP_RESPONSE, response)
            ));
        } catch (UserCertificateRevokedException e) {
            // NOTE: UserCertificateRevokedException covers both actual revocation and unknown status
            // when rejectUnknownOcspResponseStatus=false (see OcspResponseValidator.validateSubjectCertificateStatus).
            // When rejectUnknownOcspResponseStatus=true, unknown status throws UserCertificateUnknownException
            // instead, which falls through to the generic catch (Exception) block below, gets wrapped as
            // ResilientUserCertificateOCSPCheckFailedException, and triggers the circuit breaker fallback.
            // Here, wrapping as ResilientUserCertificateRevokedException ensures the circuit breaker ignores it
            // (a definitive OCSP answer, not a transient failure) and no fallback is attempted.
            RevocationInfo revocationInfo = getRevocationInfo(ocspResponderUri, e, request, response);
            throw new ResilientUserCertificateRevokedException(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
        } catch (OCSPClientException e) {
            RevocationInfo revocationInfo = getRevocationInfo(ocspResponderUri, e, request, response);
            revocationInfo.ocspResponseAttributes().put(RevocationInfo.KEY_OCSP_RESPONSE, e.getResponseBody());
            revocationInfo.ocspResponseAttributes().put(RevocationInfo.KEY_HTTP_STATUS_CODE, e.getStatusCode());
            throw new ResilientUserCertificateOCSPCheckFailedException(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
        } catch (Exception e) {
            RevocationInfo revocationInfo = getRevocationInfo(ocspResponderUri, e, request, response);
            throw new ResilientUserCertificateOCSPCheckFailedException(new ValidationInfo(subjectCertificate, List.of(revocationInfo)));
        }
    }

    private RevocationInfo getRevocationInfo(URI ocspResponderUri, Exception e, OCSPReq request, OCSPResp response) {
        RevocationInfo revocationInfo = new RevocationInfo(ocspResponderUri, new HashMap<>(Map.of(RevocationInfo.KEY_OCSP_ERROR, e)));
        if (request != null) {
            revocationInfo.ocspResponseAttributes().put(RevocationInfo.KEY_OCSP_REQUEST, request);
        }
        if (response != null) {
            revocationInfo.ocspResponseAttributes().put(RevocationInfo.KEY_OCSP_RESPONSE, response);
        }
        return revocationInfo;
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
}
