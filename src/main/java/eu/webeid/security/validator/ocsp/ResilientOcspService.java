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

import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.exceptions.UserCertificateRevokedException;
import eu.webeid.security.exceptions.UserCertificateUnknownException;
import eu.webeid.security.validator.ocsp.service.OcspService;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.decorators.Decorators;
import io.vavr.CheckedFunction0;
import io.vavr.control.Try;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

public class ResilientOcspService {
    private static final Logger LOG = LoggerFactory.getLogger(ResilientOcspService.class);

    private final OcspClient ocspClient;
    private final OcspServiceProvider ocspServiceProvider;
    private final Duration allowedOcspResponseTimeSkew;
    private final Duration maxOcspResponseThisUpdateAge;
    private final boolean rejectUnknownOcspResponseStatus;
    private final CircuitBreakerRegistry circuitBreakerRegistry;

    public ResilientOcspService(OcspClient ocspClient, OcspServiceProvider ocspServiceProvider, CircuitBreakerConfig circuitBreakerConfig, Duration allowedOcspResponseTimeSkew, Duration maxOcspResponseThisUpdateAge, boolean rejectUnknownOcspResponseStatus) {
        this.ocspClient = ocspClient;
        this.ocspServiceProvider = ocspServiceProvider;
        this.allowedOcspResponseTimeSkew = allowedOcspResponseTimeSkew;
        this.maxOcspResponseThisUpdateAge = maxOcspResponseThisUpdateAge;
        this.rejectUnknownOcspResponseStatus = rejectUnknownOcspResponseStatus;
        this.circuitBreakerRegistry = CircuitBreakerRegistry.custom()
            .withCircuitBreakerConfig(getCircuitBreakerConfig(circuitBreakerConfig))
            .build();
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

    public OcspService validateSubjectCertificateNotRevoked(X509Certificate subjectCertificate, X509Certificate issuerCertificate) throws AuthTokenException {
        final OcspService ocspService = ocspServiceProvider.getService(subjectCertificate);
        final OcspService fallbackOcspService = ocspService.getFallbackService();
        if (fallbackOcspService != null) {
            CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(ocspService.getAccessLocation().toASCIIString());
            CheckedFunction0<OcspService> primarySupplier = () -> request(ocspService, subjectCertificate, issuerCertificate);
            CheckedFunction0<OcspService> fallbackSupplier = () -> request(ocspService.getFallbackService(), subjectCertificate, issuerCertificate);
            CheckedFunction0<OcspService> decoratedSupplier = Decorators.ofCheckedSupplier(primarySupplier)
                .withCircuitBreaker(circuitBreaker)
                .withFallback(List.of(UserCertificateOCSPCheckFailedException.class, CallNotPermittedException.class, UserCertificateUnknownException.class), e -> fallbackSupplier.apply()) // TODO: Any other exceptions to trigger fallback? Resilience4j does not support Predicate<Exception> shouldFallback = e -> !(e instanceof UserCertificateRevokedException); in withFallback API.
                .decorate();

            return Try.of(decoratedSupplier).getOrElseThrow(throwable -> {
                if (throwable instanceof AuthTokenException) {
                    return (AuthTokenException) throwable;
                }
                return new UserCertificateOCSPCheckFailedException(throwable);
            });
        } else {
            return request(ocspService, subjectCertificate, issuerCertificate);
        }
    }

    private OcspService request(OcspService ocspService, X509Certificate subjectCertificate, X509Certificate issuerCertificate) throws AuthTokenException {
        try {
            final CertificateID certificateId = getCertificateId(subjectCertificate, issuerCertificate);

            final OCSPReq request = new OcspRequestBuilder()
                .withCertificateId(certificateId)
                .enableOcspNonce(ocspService.doesSupportNonce())
                .build();

            if (!ocspService.doesSupportNonce()) {
                LOG.debug("Disabling OCSP nonce extension");
            }

            LOG.debug("Sending OCSP request");
            final OCSPResp response = Objects.requireNonNull(ocspClient.request(ocspService.getAccessLocation(), request)); // TODO: This should trigger fallback?
            if (response.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
                throw new UserCertificateOCSPCheckFailedException("Response status: " + OcspResponseValidator.ocspStatusToString(response.getStatus()));
            }

            final BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
            if (basicResponse == null) {
                throw new UserCertificateOCSPCheckFailedException("Missing Basic OCSP Response");
            }

            OcspResponseValidator.validateOcspResponse(basicResponse, ocspService, allowedOcspResponseTimeSkew, maxOcspResponseThisUpdateAge, rejectUnknownOcspResponseStatus, certificateId);
            LOG.debug("OCSP check result is GOOD");

            if (ocspService.doesSupportNonce()) {
                OcspResponseValidator.validateNonce(request, basicResponse);
            }
            return ocspService;
        } catch (OCSPException | CertificateException | OperatorCreationException | IOException e) {
            throw new UserCertificateOCSPCheckFailedException(e);
        }
    }

    private static CertificateID getCertificateId(X509Certificate subjectCertificate, X509Certificate issuerCertificate) throws CertificateEncodingException, IOException, OCSPException {
        final BigInteger serial = subjectCertificate.getSerialNumber();
        final DigestCalculator digestCalculator = DigestCalculatorImpl.sha1();
        return new CertificateID(digestCalculator,
            new X509CertificateHolder(issuerCertificate.getEncoded()), serial);
    }

    private static CircuitBreakerConfig getCircuitBreakerConfig(CircuitBreakerConfig circuitBreakerConfig) {
        CircuitBreakerConfig.Builder configurationBuilder = CircuitBreakerConfig.custom() // TODO: What are good default values here?
            .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
            .slidingWindowSize(100)
            .minimumNumberOfCalls(10)
            .ignoreExceptions(UserCertificateRevokedException.class) // TODO: Revoked status is a valid response, not a failure and should be ignored. Any other exceptions to ignore?
            .automaticTransitionFromOpenToHalfOpenEnabled(true);

        if (circuitBreakerConfig != null) { // TODO: What do we allow to configure?
            configurationBuilder.slidingWindowSize(circuitBreakerConfig.getSlidingWindowSize());
            configurationBuilder.minimumNumberOfCalls(circuitBreakerConfig.getMinimumNumberOfCalls());
            configurationBuilder.failureRateThreshold(circuitBreakerConfig.getFailureRateThreshold());
            configurationBuilder.permittedNumberOfCallsInHalfOpenState(circuitBreakerConfig.getPermittedNumberOfCallsInHalfOpenState());
            configurationBuilder.waitIntervalFunctionInOpenState(circuitBreakerConfig.getWaitIntervalFunctionInOpenState());
        }

        return configurationBuilder.build();
    }

    CircuitBreakerRegistry getCircuitBreakerRegistry() {
        return circuitBreakerRegistry;
    }
}
