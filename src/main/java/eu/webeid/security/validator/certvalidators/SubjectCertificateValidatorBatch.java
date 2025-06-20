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

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.validator.AuthTokenValidationConfiguration;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;

import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public final class SubjectCertificateValidatorBatch {

    private final List<SubjectCertificateValidator> validatorList;

    public static SubjectCertificateValidatorBatch createFrom(SubjectCertificateValidator... validatorList) {
        final List<SubjectCertificateValidator> list = new ArrayList<>();
        Collections.addAll(list, validatorList);
        return new SubjectCertificateValidatorBatch(list);
    }

    public void executeFor(X509Certificate subjectCertificate) throws AuthTokenException {
        for (final SubjectCertificateValidator validator : validatorList) {
            validator.validate(subjectCertificate);
        }
    }

    public SubjectCertificateValidatorBatch addOptional(boolean condition, SubjectCertificateValidator optionalValidator) {
        if (condition) {
            validatorList.add(optionalValidator);
        }
        return this;
    }

    private SubjectCertificateValidatorBatch(List<SubjectCertificateValidator> validatorList) {
        this.validatorList = validatorList;
    }

    /**
     * Creates the certificate trust validators batch.
     * As SubjectCertificateTrustedValidator has mutable state that SubjectCertificateNotRevokedValidator depends on,
     * they cannot be reused/cached in an instance variable in a multi-threaded environment. Hence, they are
     * re-created for each validation run for thread safety.
     *
     * @return certificate trust validator batch
     */
    public static SubjectCertificateValidatorBatch forTrustValidation(
        AuthTokenValidationConfiguration configuration,
        Set<TrustAnchor> trustedCACertificateAnchors,
        CertStore trustedCACertificateCertStore,
        OcspClient ocspClient,
        OcspServiceProvider ocspServiceProvider) {

        final SubjectCertificateTrustedValidator certTrustedValidator =
            new SubjectCertificateTrustedValidator(trustedCACertificateAnchors, trustedCACertificateCertStore);

        return SubjectCertificateValidatorBatch.createFrom(
            certTrustedValidator::validateCertificateTrusted
        ).addOptional(configuration.isUserCertificateRevocationCheckWithOcspEnabled(),
            new SubjectCertificateNotRevokedValidator(
                certTrustedValidator,
                ocspClient, ocspServiceProvider,
                configuration.getAllowedOcspResponseTimeSkew(),
                configuration.getMaxOcspResponseThisUpdateAge()
            )::validateCertificateNotRevoked
        );
    }
}
