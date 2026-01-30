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
import eu.webeid.ocsp.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.ocsp.exceptions.UserCertificateRevokedException;
import eu.webeid.ocsp.exceptions.UserCertificateUnknownException;
import eu.webeid.ocsp.protocol.OcspRequestBuilder;
import eu.webeid.ocsp.service.OcspService;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.security.exceptions.AuthTokenException;
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
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
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
            throw new UserCertificateOCSPCheckFailedException(e, null);
        }
        final OcspService fallbackOcspService = ocspService.getFallbackService();
        if (fallbackOcspService == null) {
            return List.of(request(ocspService, subjectCertificate, issuerCertificate, false));
        }

        CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(ocspService.getAccessLocation().toASCIIString());
        CheckedFunction0<RevocationInfo> primarySupplier = () -> request(ocspService, subjectCertificate, issuerCertificate, false);
        CheckedFunction0<RevocationInfo> fallbackSupplier = () -> request(ocspService.getFallbackService(), subjectCertificate, issuerCertificate, true);
        Decorators.DecorateCheckedSupplier<RevocationInfo> decorateCheckedSupplier = Decorators.ofCheckedSupplier(primarySupplier);
        if (retryRegistry != null) {
            Retry retry = retryRegistry.retry(ocspService.getAccessLocation().toASCIIString());
            decorateCheckedSupplier.withRetry(retry);
        }
        decorateCheckedSupplier.withCircuitBreaker(circuitBreaker)
            .withFallback(List.of(UserCertificateOCSPCheckFailedException.class, CallNotPermittedException.class, UserCertificateUnknownException.class), e -> fallbackSupplier.apply());

        CheckedFunction0<RevocationInfo> decoratedSupplier = decorateCheckedSupplier.decorate();

        // TODO Collect the intermediate results
        return List.of(Try.of(decoratedSupplier).getOrElseThrow(throwable -> {
            if (throwable instanceof AuthTokenException) {
                return (AuthTokenException) throwable;
            }
            return new UserCertificateOCSPCheckFailedException(throwable, null);
        }));
    }

    private RevocationInfo request(OcspService ocspService, X509Certificate subjectCertificate, X509Certificate issuerCertificate, boolean allowThisUpdateInPast) throws AuthTokenException {
        URI ocspResponderUri = null;
        try {
            ocspResponderUri = requireNonNull(ocspService.getAccessLocation(), "ocspResponderUri");

            final CertificateID certificateId = getCertificateId(subjectCertificate, issuerCertificate);
            final OCSPReq request = new OcspRequestBuilder()
                .withCertificateId(certificateId)
                .enableOcspNonce(ocspService.doesSupportNonce())
                .build();

            if (!ocspService.doesSupportNonce()) {
                LOG.debug("Disabling OCSP nonce extension");
            }

            LOG.debug("Sending OCSP request");
            OCSPResp response = requireNonNull(getOcspClient().request(ocspResponderUri, request)); // TODO: This should trigger fallback?
            if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                throw new UserCertificateOCSPCheckFailedException("Response status: " + ocspStatusToString(response.getStatus()), ocspResponderUri);
            }

            final BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
            if (basicResponse == null) {
                throw new UserCertificateOCSPCheckFailedException("Missing Basic OCSP Response", ocspResponderUri);
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
        } catch (OCSPException | CertificateException | OperatorCreationException | IOException e) {
            throw new UserCertificateOCSPCheckFailedException(e, ocspResponderUri);
        }
    }

    private static CircuitBreakerConfig getCircuitBreakerConfig(CircuitBreakerConfig circuitBreakerConfig) {
        return CircuitBreakerConfig.from(circuitBreakerConfig)
            // Users must not be able to modify these three values.
            .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
            .ignoreExceptions(UserCertificateRevokedException.class)
            .automaticTransitionFromOpenToHalfOpenEnabled(true)
            .build();
    }

    private static RetryConfig getRetryConfig(RetryConfig retryConfig) {
        return RetryConfig.from(retryConfig)
            // Users must not be able to modify this value.
            .ignoreExceptions(UserCertificateRevokedException.class)
            .build();
    }
}
