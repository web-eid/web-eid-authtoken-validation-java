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

package eu.webeid.security.validator.versionvalidators;

import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.validator.AuthTokenSignatureValidator;
import eu.webeid.security.validator.AuthTokenValidationConfiguration;
import eu.webeid.security.validator.certvalidators.SubjectCertificateValidatorBatch;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;

import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

class AuthTokenVersion1Validator implements AuthTokenVersionValidator {

    private static final String V1_SUPPORTED_TOKEN_FORMAT_PREFIX = "web-eid:1";
    private static final Pattern V1_SUPPORTED_TOKEN_FORMAT_PATTERN = Pattern.compile("^web-eid:1(?:\\.\\d+)?$");
    private final SubjectCertificateValidatorBatch simpleSubjectCertificateValidators;
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private final AuthTokenSignatureValidator authTokenSignatureValidator;
    private final AuthTokenValidationConfiguration configuration;
    private final OcspClient ocspClient;
    private final OcspServiceProvider ocspServiceProvider;

    public AuthTokenVersion1Validator(
        SubjectCertificateValidatorBatch simpleSubjectCertificateValidators,
        Set<TrustAnchor> trustedCACertificateAnchors,
        CertStore trustedCACertificateCertStore,
        AuthTokenSignatureValidator authTokenSignatureValidator,
        AuthTokenValidationConfiguration configuration,
        OcspClient ocspClient,
        OcspServiceProvider ocspServiceProvider
    ) {
        this.simpleSubjectCertificateValidators = simpleSubjectCertificateValidators;
        this.trustedCACertificateAnchors = trustedCACertificateAnchors;
        this.trustedCACertificateCertStore = trustedCACertificateCertStore;
        this.authTokenSignatureValidator = authTokenSignatureValidator;
        this.configuration = configuration;
        this.ocspClient = ocspClient;
        this.ocspServiceProvider = ocspServiceProvider;
    }

    @Override
    public boolean supports(String format) {
        return format != null && getSupportedFormatPattern().matcher(format).matches();
    }

    protected Pattern getSupportedFormatPattern() {
        return V1_SUPPORTED_TOKEN_FORMAT_PATTERN;
    }

    @Override
    public X509Certificate validate(WebEidAuthToken token, String currentChallengeNonce) throws AuthTokenException {
        return validate(token, currentChallengeNonce, null);
    }

    protected X509Certificate validate(WebEidAuthToken token, String currentChallengeNonce, List<X509Certificate> intermediateCertificates) throws AuthTokenException {
        if (isExactV10Format(token.getFormat())) {
            if (token.getUnverifiedSigningCertificates() != null) {
                throw new AuthTokenParseException(
                    "'unverifiedSigningCertificates' field is not allowed for format '" + token.getFormat() + "'"
                );
            }
            if (token.getUnverifiedIntermediateCertificates() != null) {
                throw new AuthTokenParseException(
                    "'unverifiedIntermediateCertificates' field is not allowed for format '" + token.getFormat() + "'"
                );
            }
        }

        if (token.getUnverifiedCertificate() == null || token.getUnverifiedCertificate().isEmpty()) {
            throw new AuthTokenParseException("'unverifiedCertificate' field is missing, null or empty");
        }

        final X509Certificate subjectCertificate = CertificateLoader.decodeCertificateFromBase64(token.getUnverifiedCertificate());

        simpleSubjectCertificateValidators.executeFor(subjectCertificate);

        SubjectCertificateValidatorBatch.forTrustValidation(
            configuration,
            trustedCACertificateAnchors,
            trustedCACertificateCertStore,
            intermediateCertificates,
            ocspClient,
            ocspServiceProvider
        ).executeFor(subjectCertificate);

        // It is guaranteed that if the signature verification succeeds, then the origin and challenge
        // have been implicitly and correctly verified without the need to implement any additional checks.
        authTokenSignatureValidator.validate(
            token.getAlgorithm(),
            token.getSignature(),
            subjectCertificate.getPublicKey(),
            currentChallengeNonce
        );

        return subjectCertificate;
    }

    private static boolean isExactV10Format(String format) {
        return V1_SUPPORTED_TOKEN_FORMAT_PREFIX.equals(format) || "web-eid:1.0".equals(format);
    }

    protected Set<TrustAnchor> getTrustedCACertificateAnchors() {
        return trustedCACertificateAnchors;
    }

    protected CertStore getTrustedCACertificateCertStore() {
        return trustedCACertificateCertStore;
    }
}
