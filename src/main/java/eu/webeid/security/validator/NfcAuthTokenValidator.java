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

import eu.webeid.security.authtoken.SupportedSignatureAlgorithm;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.validator.certvalidators.SubjectCertificateValidatorBatch;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static eu.webeid.security.util.Strings.isNullOrEmpty;

public class NfcAuthTokenValidator {

    private final SubjectCertificateValidatorBatch simpleSubjectCertificateValidators;
    private final SubjectCertificateValidatorBatch certTrustValidators;

    NfcAuthTokenValidator(
        SubjectCertificateValidatorBatch simpleSubjectCertificateValidators,
        SubjectCertificateValidatorBatch certTrustValidators
    ) {
        this.simpleSubjectCertificateValidators = simpleSubjectCertificateValidators;
        this.certTrustValidators = certTrustValidators;
    }

    void validate(WebEidAuthToken token, X509Certificate subjectCertificate) throws AuthTokenException {
        if (isNullOrEmpty(token.getUnverifiedSigningCertificate())) {
            throw new AuthTokenParseException("'unverifiedSigningCertificate' field is missing, null or empty for format 'web-eid:1.1'");
        }

        if (token.getSupportedSignatureAlgorithms() == null || token.getSupportedSignatureAlgorithms().isEmpty()) {
            throw new AuthTokenParseException("'supportedSignatureAlgorithms' field is missing");
        }

        validateSupportedSignatureAlgorithms(token.getSupportedSignatureAlgorithms());

        final X509Certificate signingCertificate = CertificateLoader.decodeCertificateFromBase64(token.getUnverifiedSigningCertificate());

        if (!subjectCertificate.getSubjectX500Principal().equals(signingCertificate.getSubjectX500Principal())) {
            throw new AuthTokenParseException("Signing certificate subject does not match authentication certificate subject");
        }

        simpleSubjectCertificateValidators.executeFor(signingCertificate);
        certTrustValidators.executeFor(signingCertificate);
    }

    private static void validateSupportedSignatureAlgorithms(List<SupportedSignatureAlgorithm> algorithms) throws AuthTokenParseException {
        boolean hasInvalid = algorithms.stream().anyMatch(supportedSignatureAlgorithm ->
                   !isValidCryptoAlgorithm(supportedSignatureAlgorithm.getCryptoAlgorithm())
                || !isValidHashFunction(supportedSignatureAlgorithm.getHashFunction())
                || !isValidPaddingScheme(supportedSignatureAlgorithm.getPaddingScheme())
        );

        if (hasInvalid) {
            throw new AuthTokenParseException("Unsupported signature algorithm");
        }
    }

    private static boolean isValidCryptoAlgorithm(String value) {
        return "RSA".equals(value) || "ECC".equals(value);
    }

    private static boolean isValidHashFunction(String value) {
        return Set.of(
            "SHA-224", "SHA-256", "SHA-384", "SHA-512",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
        ).contains(value);
    }

    private static boolean isValidPaddingScheme(String value) {
        return "NONE".equals(value) || "PKCS1.5".equals(value) || "PSS".equals(value);
    }
}
