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

package eu.webeid.security.validator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.certvalidators.SubjectCertificatePolicyValidator;
import eu.webeid.security.validator.certvalidators.SubjectCertificatePurposeValidator;
import eu.webeid.ocsp.service.OcspServiceProvider;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Provides the default implementation of {@link AuthTokenValidator}.
 */
final class AuthTokenValidatorImpl implements AuthTokenValidator {

    private static final int TOKEN_MIN_LENGTH = 100;
    private static final int TOKEN_MAX_LENGTH = 10000;
    private static final Logger LOG = LoggerFactory.getLogger(AuthTokenValidatorImpl.class);

    private static final ObjectReader OBJECT_READER = new ObjectMapper().readerFor(WebEidAuthToken.class);

    private final AuthTokenValidationConfiguration configuration;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    // OcspClient uses built-in HttpClient internally by default.
    // A single HttpClient instance is reused for all HTTP calls to utilize connection and thread pools.
    private OcspServiceProvider ocspServiceProvider;
    private final AuthTokenSignatureValidator authTokenSignatureValidator;
    private final SubjectCertificatePolicyValidator subjectCertificatePolicyValidator;

    /**
     * @param configuration configuration parameters for the token validator
     */
    AuthTokenValidatorImpl(AuthTokenValidationConfiguration configuration) throws JceException {
        // Copy the configuration object to make AuthTokenValidatorImpl immutable and thread-safe.
        this.configuration = configuration.copy();

        // Create and cache trusted CA certificate JCA objects for SubjectCertificateTrustedValidator and AiaOcspService.
        trustedCACertificateAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(configuration.getTrustedCACertificates());
        trustedCACertificateCertStore = CertificateValidator.buildCertStoreFromCertificates(configuration.getTrustedCACertificates());

        subjectCertificatePolicyValidator = new SubjectCertificatePolicyValidator(configuration.getDisallowedSubjectCertificatePolicies());

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
    public ValidationInfo validate(WebEidAuthToken authToken, String currentChallengeNonce) throws AuthTokenException {
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
            final WebEidAuthToken token = OBJECT_READER.readValue(authToken);
            if (token == null) {
                throw new AuthTokenParseException("Web eID authentication token is null");
            }
            return token;
        } catch (IOException e) {
            throw new AuthTokenParseException("Error parsing Web eID authentication token", e);
        }
    }

    private ValidationInfo validateToken(WebEidAuthToken token, String currentChallengeNonce) throws AuthTokenException {
        if (token.format() == null || !token.format().startsWith(CURRENT_TOKEN_FORMAT_VERSION)) {
            throw new AuthTokenParseException("Only token format version '" + CURRENT_TOKEN_FORMAT_VERSION +
                "' is currently supported");
        }
        if (token.unverifiedCertificate() == null || token.unverifiedCertificate().isEmpty()) {
            throw new AuthTokenParseException("'unverifiedCertificate' field is missing, null or empty");
        }
        final X509Certificate subjectCertificate = CertificateLoader.decodeCertificateFromBase64(token.unverifiedCertificate());

        SubjectCertificatePurposeValidator.validateCertificatePurpose(subjectCertificate);
        subjectCertificatePolicyValidator.validateCertificatePolicies(subjectCertificate);

        // Use the clock instance so that the date can be mocked in tests.
        final Date now = DateAndTime.DefaultClock.getInstance().now();

        final List<RevocationInfo> revocationInfoList = CertificateValidator.validateCertificateTrustAndRevocation(
                subjectCertificate,
                trustedCACertificateAnchors,
                trustedCACertificateCertStore,
                now,
                configuration.getRevocationMode(),
                configuration.getCertificateRevocationChecker(),
                configuration.getPkixRevocationChecker()
        );
        LOG.debug("Subject certificate is valid and signed by a trusted CA");

        // It is guaranteed that if the signature verification succeeds, then the origin and challenge
        // have been implicitly and correctly verified without the need to implement any additional checks.
        authTokenSignatureValidator.validate(token.algorithm(),
            token.signature(),
            subjectCertificate.getPublicKey(),
            currentChallengeNonce
        );

        return new ValidationInfo(subjectCertificate, revocationInfoList);
    }

}
