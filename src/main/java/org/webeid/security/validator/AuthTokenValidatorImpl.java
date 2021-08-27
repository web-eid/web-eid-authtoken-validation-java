/*
 * Copyright (c) 2020 The Web eID Project
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

package org.webeid.security.validator;

import com.google.common.base.Suppliers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.webeid.security.exceptions.JceException;
import org.webeid.security.exceptions.TokenParseException;
import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.validator.ocsp.OcspClient;
import org.webeid.security.validator.ocsp.OcspClientImpl;
import org.webeid.security.validator.ocsp.OcspServiceProvider;
import org.webeid.security.validator.validators.*;

import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.function.Supplier;

import static org.webeid.security.certificate.CertificateValidator.buildCertStoreFromCertificates;
import static org.webeid.security.certificate.CertificateValidator.buildTrustAnchorsFromCertificates;

/**
 * Provides the default implementation of {@link AuthTokenValidator}.
 */
final class AuthTokenValidatorImpl implements AuthTokenValidator {

    private static final int TOKEN_MIN_LENGTH = 100;
    private static final int TOKEN_MAX_LENGTH = 10000;
    private static final Logger LOG = LoggerFactory.getLogger(AuthTokenValidatorImpl.class);

    private final AuthTokenValidationConfiguration configuration;
    // OkHttp performs best when a single OkHttpClient instance is created and reused for all HTTP calls.
    // This is because each client holds its own connection pool and thread pools.
    // Reusing connections and threads reduces latency and saves memory.
    private final Supplier<OcspClient> ocspClientSupplier;
    private final ValidatorBatch simpleSubjectCertificateValidators;
    private final ValidatorBatch tokenBodyValidators;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private OcspServiceProvider ocspServiceProvider;

    /**
     * @param configuration configuration parameters for the token validator
     */
    AuthTokenValidatorImpl(AuthTokenValidationConfiguration configuration) throws JceException {
        // Copy the configuration object to make AuthTokenValidatorImpl immutable and thread-safe.
        this.configuration = configuration.copy();
        // Lazy initialization, avoid constructing the OkHttpClient object when certificate revocation check is not enabled.
        // Returns a supplier which caches the instance retrieved during the first call to get() and returns
        // that value on subsequent calls to get(). The returned supplier is thread-safe.
        // The OkHttpClient build() method will be invoked at most once.
        this.ocspClientSupplier = Suppliers.memoize(() -> OcspClientImpl.build(configuration.getOcspRequestTimeout()));

        simpleSubjectCertificateValidators = ValidatorBatch.createFrom(
            FunctionalSubjectCertificateValidators::validateCertificateExpiry,
            FunctionalSubjectCertificateValidators::validateCertificatePurpose,
            new SubjectCertificatePolicyValidator(configuration.getDisallowedSubjectCertificatePolicies())::validateCertificatePolicies
        );
        tokenBodyValidators = ValidatorBatch.createFrom(
            new NonceValidator(configuration.getNonceCache())::validateNonce,
            new OriginValidator(configuration.getSiteOrigin())::validateOrigin
        ).addOptional(configuration.isSiteCertificateFingerprintValidationEnabled(),
            new SiteCertificateFingerprintValidator(configuration.getSiteCertificateSha256Fingerprint())::validateSiteCertificateFingerprint
        );

        // Create and cache trusted CA certificate JCA objects for SubjectCertificateTrustedValidator.
        trustedCACertificateAnchors = buildTrustAnchorsFromCertificates(configuration.getTrustedCACertificates());
        trustedCACertificateCertStore = buildCertStoreFromCertificates(configuration.getTrustedCACertificates());

        if (configuration.isUserCertificateRevocationCheckWithOcspEnabled()) {
            ocspServiceProvider = configuration.getAiaOcspServiceConfiguration() != null ?
                new OcspServiceProvider(configuration.getAiaOcspServiceConfiguration()) :
                new OcspServiceProvider(configuration.getDesignatedOcspServiceConfiguration());
        }
    }

    @Override
    public X509Certificate validate(String authToken) throws TokenValidationException {

        if (authToken == null || authToken.length() < TOKEN_MIN_LENGTH) {
            throw new TokenParseException("Auth token is null or too short");
        }
        if (authToken.length() > TOKEN_MAX_LENGTH) {
            throw new TokenParseException("Auth token is too long");
        }

        try {
            LOG.info("Starting token parsing and validation");
            final AuthTokenParser authTokenParser = new AuthTokenParser(authToken, configuration.getAllowedClientClockSkew());
            final AuthTokenValidatorData actualTokenData = authTokenParser.parseHeaderFromTokenString();

            simpleSubjectCertificateValidators.executeFor(actualTokenData);

            getCertTrustValidators().executeFor(actualTokenData);

            authTokenParser.validateTokenSignatureAndParseClaims();
            authTokenParser.populateDataFromClaims(actualTokenData);

            tokenBodyValidators.executeFor(actualTokenData);

            LOG.info("Token parsing and validation successful");
            return actualTokenData.getSubjectCertificate();

        } catch (Exception e) {
            // Generally "log and rethrow" is an anti-pattern, but it fits with the surrounding logging style.
            LOG.warn("Token parsing and validation was interrupted:", e);
            throw e;
        }
    }

    /**
     * Creates the certificate trust validator batch.
     * As SubjectCertificateTrustedValidator has mutable state that SubjectCertificateNotRevokedValidator depends on,
     * they cannot be reused/cached in an instance variable in a multi-threaded environment. Hence they are
     * re-created for each validation run for thread safety.
     *
     * @return certificate trust validator batch
     */
    private ValidatorBatch getCertTrustValidators() {
        final SubjectCertificateTrustedValidator certTrustedValidator =
            new SubjectCertificateTrustedValidator(trustedCACertificateAnchors, trustedCACertificateCertStore);
        return ValidatorBatch.createFrom(
            certTrustedValidator::validateCertificateTrusted
        ).addOptional(configuration.isUserCertificateRevocationCheckWithOcspEnabled(),
            new SubjectCertificateNotRevokedValidator(certTrustedValidator, ocspClientSupplier.get(), ocspServiceProvider)::validateCertificateNotRevoked
        );
    }
}
