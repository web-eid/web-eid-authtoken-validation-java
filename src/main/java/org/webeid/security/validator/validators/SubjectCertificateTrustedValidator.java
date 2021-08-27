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

package org.webeid.security.validator.validators;

import org.webeid.security.exceptions.TokenValidationException;
import org.webeid.security.exceptions.CertificateNotTrustedException;
import org.webeid.security.validator.AuthTokenValidatorData;

import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;

import static org.webeid.security.certificate.CertificateValidator.validateIsSignedByTrustedCA;

public final class SubjectCertificateTrustedValidator {


    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private X509Certificate subjectCertificateIssuerCertificate;

    public SubjectCertificateTrustedValidator(Set<TrustAnchor> trustedCACertificateAnchors, CertStore trustedCACertificateCertStore) {
        this.trustedCACertificateAnchors = trustedCACertificateAnchors;
        this.trustedCACertificateCertStore = trustedCACertificateCertStore;
    }

    /**
     * Validates that the user certificate from the authentication token is signed by a trusted certificate authority.
     *
     * @param actualTokenData authentication token data that contains the user certificate.
     * @throws CertificateNotTrustedException when user certificate is not signed by a trusted CA.
     */
    public void validateCertificateTrusted(AuthTokenValidatorData actualTokenData) throws TokenValidationException {
        final X509Certificate certificate = actualTokenData.getSubjectCertificate();
        subjectCertificateIssuerCertificate = validateIsSignedByTrustedCA(certificate, trustedCACertificateAnchors, trustedCACertificateCertStore);
    }

    public X509Certificate getSubjectCertificateIssuerCertificate() {
        return subjectCertificateIssuerCertificate;
    }
}
