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

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.AuthTokenSignatureValidator;
import eu.webeid.security.validator.AuthTokenValidationConfiguration;
import eu.webeid.security.validator.certvalidators.SubjectCertificatePolicyValidator;
import eu.webeid.security.validator.certvalidators.SubjectCertificatePurposeValidator;
import eu.webeid.security.validator.certvalidators.SubjectCertificateValidatorBatch;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import eu.webeid.security.validator.ocsp.service.AiaOcspServiceConfiguration;

import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public final class AuthTokenVersionValidatorFactory {
    private final List<AuthTokenVersionValidator> validators;

    AuthTokenVersionValidatorFactory(List<AuthTokenVersionValidator> validators) {
        this.validators = validators;
    }

    boolean supports(String format) {
        return validators.stream().anyMatch(v -> v.supports(format));
    }

    public AuthTokenVersionValidator getValidatorFor(String format) throws AuthTokenParseException {
        return validators.stream()
                .filter(v -> v.supports(format))
                .findFirst()
                .orElseThrow(() -> new AuthTokenParseException(
                        "Token format version '" + format + "' is currently not supported"));
    }

    public static AuthTokenVersionValidatorFactory create(AuthTokenValidationConfiguration configuration, OcspClient ocspClient) throws JceException {
        // Copy the configuration object to make AuthTokenVersionValidatorFactory immutable and thread-safe.
        final AuthTokenValidationConfiguration validationConfig = configuration.copy();

        // Create and cache trusted CA certificate JCA objects for SubjectCertificateTrustedValidator and AiaOcspService.
        final Set<TrustAnchor> trustedCACertificateAnchors = CertificateValidator.buildTrustAnchorsFromCertificates(validationConfig.getTrustedCACertificates());
        final CertStore trustedCACertificateCertStore = CertificateValidator.buildCertStoreFromCertificates(validationConfig.getTrustedCACertificates());

        final SubjectCertificateValidatorBatch simpleSubjectCertificateValidators = SubjectCertificateValidatorBatch.createFrom(
                SubjectCertificatePurposeValidator::validateCertificatePurpose,
                new SubjectCertificatePolicyValidator(validationConfig.getDisallowedSubjectCertificatePolicies())::validateCertificatePolicies
        );

        // OcspClient uses built-in HttpClient internally by default.
        // A single HttpClient instance is reused for all HTTP calls to utilize connection and thread pools.
        // The OCSP client may be provided by the API consumer.
        OcspServiceProvider ocspServiceProvider = null;
        if (validationConfig.isUserCertificateRevocationCheckWithOcspEnabled()) {
            Objects.requireNonNull(ocspClient, "OCSP client must not be null when OCSP check is enabled");
            ocspServiceProvider = new OcspServiceProvider(
                    validationConfig.getDesignatedOcspServiceConfiguration(),
                    new AiaOcspServiceConfiguration(
                            validationConfig.getNonceDisabledOcspUrls(),
                            trustedCACertificateAnchors,
                            trustedCACertificateCertStore));
        }

        final AuthTokenSignatureValidator authTokenSignatureValidator =
                new AuthTokenSignatureValidator(validationConfig.getSiteOrigin());

        return new AuthTokenVersionValidatorFactory(List.of(
                new AuthTokenVersion11Validator(
                        simpleSubjectCertificateValidators,
                        trustedCACertificateAnchors,
                        trustedCACertificateCertStore,
                        authTokenSignatureValidator,
                        validationConfig,
                        ocspClient,
                        ocspServiceProvider
                ),
                new AuthTokenVersion1Validator(
                        simpleSubjectCertificateValidators,
                        trustedCACertificateAnchors,
                        trustedCACertificateCertStore,
                        authTokenSignatureValidator,
                        validationConfig,
                        ocspClient,
                        ocspServiceProvider
                )
        ));
    }
}
