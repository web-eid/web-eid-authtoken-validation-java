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
import eu.webeid.security.validator.ocsp.OcspValidationInfo;
import eu.webeid.security.validator.ocsp.ResilientOcspService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Objects;

public final class SubjectCertificateNotRevokedValidator {

    private final SubjectCertificateTrustedValidator trustValidator;
    private final ResilientOcspService resilientOcspService;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public SubjectCertificateNotRevokedValidator(ResilientOcspService resilientOcspService, SubjectCertificateTrustedValidator trustValidator) {
        this.resilientOcspService = resilientOcspService;
        this.trustValidator = trustValidator;
    }

    /**
     * Validates that the user certificate from the authentication token is not revoked with OCSP.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws AuthTokenException when user certificate is revoked or revocation check fails.
     */
    public OcspValidationInfo validateCertificateNotRevoked(X509Certificate subjectCertificate) throws AuthTokenException {
        final X509Certificate issuerCertificate = Objects.requireNonNull(trustValidator.getSubjectCertificateIssuerCertificate());
        return resilientOcspService.validateSubjectCertificateNotRevoked(subjectCertificate, issuerCertificate);
    }
}
