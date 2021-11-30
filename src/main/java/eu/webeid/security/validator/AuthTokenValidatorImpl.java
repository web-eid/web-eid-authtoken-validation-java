/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

package eu.webeid.security.validator;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.validator.certvalidators.SubjectCertificateExpiryValidator;
import eu.webeid.security.validator.certvalidators.SubjectCertificateNotRevokedValidator;
import eu.webeid.security.validator.certvalidators.SubjectCertificatePolicyValidator;
import eu.webeid.security.validator.certvalidators.SubjectCertificatePurposeValidator;
import eu.webeid.security.validator.certvalidators.SubjectCertificateTrustedValidator;
import eu.webeid.security.validator.certvalidators.SubjectCertificateValidatorBatch;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspClientImpl;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import eu.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * Provides the default implementation of {@link AuthTokenValidator}.
 */
final class AuthTokenValidatorImpl implements AuthTokenValidator {

    private static final int TOKEN_MIN_LENGTH = 100;
    private static final int TOKEN_MAX_LENGTH = 10000;
    private static final Logger LOG = LoggerFactory.getLogger(AuthTokenValidatorImpl.class);

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final AuthTokenValidationConfiguration configuration;
    private final SubjectCertificateValidatorBatch simpleSubjectCertificateValidators;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    // OcspClient uses OkHttp internally.
    // OkHttp performs best when a single OkHttpClient instance is created and reused for all HTTP calls.
    // This is because each client holds its own connection pool and thread pools.
    // Reusing connections and threads reduces latency and saves memory.
    private OcspClient ocspClient;
    private OcspServiceProvider ocspServiceProvider;
    private final AuthTokenSignatureValidator authTokenSignatureValidator;

    /**
     * @param configuration configuration parameters for the token validator
     */
    AuthTokenValidatorImpl(AuthTokenValidationConfiguration configuration) throws JceException {
        // Copy the configuration object to make AuthTokenValidatorImpl immutable and thread-safe.
        this.configuration = configuration.copy();

        // Create and cache trusted CA certificate JCA objects for SubjectCertificateTrustedValidator and AiaOcspService.
        trustedCACertificateAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(configuration.getTrustedCACertificates());
        trustedCACertificateCertStore = CertificateValidator.buildCertStoreFromCertificates(configuration.getTrustedCACertificates());

        simpleSubjectCertificateValidators = SubjectCertificateValidatorBatch.createFrom(
            new SubjectCertificateExpiryValidator(trustedCACertificateAnchors)::validateCertificateExpiry,
            SubjectCertificatePurposeValidator::validateCertificatePurpose,
            new SubjectCertificatePolicyValidator(configuration.getDisallowedSubjectCertificatePolicies())::validateCertificatePolicies
        );

        if (configuration.isUserCertificateRevocationCheckWithOcspEnabled()) {
            ocspClient = OcspClientImpl.build(configuration.getOcspRequestTimeout());
            ocspServiceProvider = new OcspServiceProvider(
                configuration.getDesignatedOcspServiceConfiguration(),
                new AiaOcspServiceConfiguration(configuration.getNonceDisabledOcspUrls(),
                    trustedCACertificateAnchors,
                    trustedCACertificateCertStore));
        }

        authTokenSignatureValidator = new AuthTokenSignatureValidator(configuration.getSiteOrigin());
    }

    @Override
    public WebEidAuthToken parse(String authToken) throws AuthTokenException {
        try {
            LOG.info("Starting token parsing");
            validateTokenLength(authToken);
            return parseToken(authToken);
        } catch (Exception e) {
            // Generally "log and rethrow" is an anti-pattern, but it fits with the surrounding logging style.
            LOG.warn("Token parsing was interrupted:", e);
            throw e;
        }
    }

    @Override
    public X509Certificate validate(WebEidAuthToken authToken, String currentChallengeNonce) throws AuthTokenException {
        try {
            LOG.info("Starting token validation");
            return validateToken(authToken, currentChallengeNonce);
        } catch (Exception e) {
            // Generally "log and rethrow" is an anti-pattern, but it fits with the surrounding logging style.
            LOG.warn("Token validation was interrupted:", e);
            throw e;
        }
    }

    private void validateTokenLength(String authToken) throws AuthTokenParseException {
        if (authToken == null || authToken.length() < TOKEN_MIN_LENGTH) {
            throw new AuthTokenParseException("Auth token is null or too short");
        }
        if (authToken.length() > TOKEN_MAX_LENGTH) {
            throw new AuthTokenParseException("Auth token is too long");
        }
    }

    private WebEidAuthToken parseToken(String authToken) throws AuthTokenParseException {
        try {
            final WebEidAuthToken token = objectMapper.readValue(authToken, WebEidAuthToken.class);
            if (token == null) {
                throw new AuthTokenParseException("Web eID authentication token is null");
            }
            return token;
        } catch (IOException e) {
            throw new AuthTokenParseException("Error parsing Web eID authentication token", e);
        }
    }

    private X509Certificate validateToken(WebEidAuthToken token, String currentChallengeNonce) throws AuthTokenException {
        if (token.getFormat() == null || !token.getFormat().startsWith(CURRENT_TOKEN_FORMAT_VERSION)) {
            throw new AuthTokenParseException("Only token format version '" + CURRENT_TOKEN_FORMAT_VERSION +
                "' is currently supported");
        }
        if (token.getUnverifiedCertificate() == null || token.getUnverifiedCertificate().isEmpty()) {
            throw new AuthTokenParseException("'unverifiedCertificate' field is missing, null or empty");
        }
        final X509Certificate subjectCertificate = CertificateLoader.decodeCertificateFromBase64(token.getUnverifiedCertificate());

        simpleSubjectCertificateValidators.executeFor(subjectCertificate);
        getCertTrustValidators().executeFor(subjectCertificate);

        // It is guaranteed that if the signature verification succeeds, then the origin, challenge
        // and, if part of the signature, origin certificate have been implicitly and correctly verified
        // without the need to implement any additional checks.
        authTokenSignatureValidator.validate(token.getAlgorithm(),
            token.getSignature(),
            subjectCertificate.getPublicKey(),
            currentChallengeNonce);

        return subjectCertificate;
    }

    /**
     * Creates the certificate trust validators batch.
     * As SubjectCertificateTrustedValidator has mutable state that SubjectCertificateNotRevokedValidator depends on,
     * they cannot be reused/cached in an instance variable in a multi-threaded environment. Hence, they are
     * re-created for each validation run for thread safety.
     *
     * @return certificate trust validator batch
     */
    private SubjectCertificateValidatorBatch getCertTrustValidators() {
        final SubjectCertificateTrustedValidator certTrustedValidator =
            new SubjectCertificateTrustedValidator(trustedCACertificateAnchors, trustedCACertificateCertStore);
        return SubjectCertificateValidatorBatch.createFrom(
            certTrustedValidator::validateCertificateTrusted
        ).addOptional(configuration.isUserCertificateRevocationCheckWithOcspEnabled(),
            new SubjectCertificateNotRevokedValidator(certTrustedValidator, ocspClient, ocspServiceProvider)::validateCertificateNotRevoked
        );
    }

}
