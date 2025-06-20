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

import eu.webeid.security.authtoken.SupportedSignatureAlgorithm;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.CertificateDecodingException;
import eu.webeid.security.validator.AuthTokenSignatureValidator;
import eu.webeid.security.validator.AuthTokenValidationConfiguration;
import eu.webeid.security.validator.certvalidators.SubjectCertificateValidatorBatch;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import javax.security.auth.x500.X500Principal;
import java.security.cert.CertStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static eu.webeid.security.util.Strings.isNullOrEmpty;

class AuthTokenVersion11Validator extends AuthTokenVersion1Validator implements AuthTokenVersionValidator {

    private static final String V11_SUPPORTED_TOKEN_FORMAT_PREFIX = "web-eid:1.1";
    private static final Set<String> SUPPORTED_SIGNING_CRYPTO_ALGORITHMS = Set.of("ECC", "RSA");
    private static final Set<String> SUPPORTED_SIGNING_PADDING_SCHEMES = Set.of("NONE", "PKCS1.5", "PSS");
    private static final Set<String> SUPPORTED_SIGNING_HASH_FUNCTIONS = Set.of(
        "SHA-224", "SHA-256", "SHA-384", "SHA-512",
        "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
    );
    private static final int KEY_USAGE_NON_REPUDIATION = 1;

    public AuthTokenVersion11Validator(
        SubjectCertificateValidatorBatch simpleSubjectCertificateValidators,
        Set<TrustAnchor> trustedCACertificateAnchors,
        CertStore trustedCACertificateCertStore,
        AuthTokenSignatureValidator authTokenSignatureValidator,
        AuthTokenValidationConfiguration configuration,
        OcspClient ocspClient,
        OcspServiceProvider ocspServiceProvider
    ) {
        super(
            simpleSubjectCertificateValidators,
            trustedCACertificateAnchors,
            trustedCACertificateCertStore,
            authTokenSignatureValidator,
            configuration,
            ocspClient,
            ocspServiceProvider
        );
    }

    @Override
    protected String getSupportedFormatPrefix() {
        return V11_SUPPORTED_TOKEN_FORMAT_PREFIX;
    }

    @Override
    public X509Certificate validate(WebEidAuthToken token, String currentChallengeNonce) throws AuthTokenException {
        final X509Certificate subjectCertificate = validateV1(token, currentChallengeNonce);
        final X509Certificate signingCertificate = validateSigningCertificateExists(token);
        validateSupportedSignatureAlgorithms(token.getSupportedSignatureAlgorithms());
        validateSameSubject(subjectCertificate, signingCertificate);
        validateSameIssuer(subjectCertificate, signingCertificate);
        validateSigningCertificateValidity(signingCertificate);
        validateKeyUsage(signingCertificate);

        return subjectCertificate;
    }

    private static void validateSupportedSignatureAlgorithms(List<SupportedSignatureAlgorithm> algorithms) throws AuthTokenParseException {
        if (algorithms == null || algorithms.isEmpty()) {
            throw new AuthTokenParseException("'supportedSignatureAlgorithms' field is missing");
        }

        boolean hasInvalid = algorithms.stream().anyMatch(supportedSignatureAlgorithm ->
            !SUPPORTED_SIGNING_CRYPTO_ALGORITHMS.contains(supportedSignatureAlgorithm.getCryptoAlgorithm()) ||
                !SUPPORTED_SIGNING_HASH_FUNCTIONS.contains(supportedSignatureAlgorithm.getHashFunction()) ||
                !SUPPORTED_SIGNING_PADDING_SCHEMES.contains(supportedSignatureAlgorithm.getPaddingScheme())
        );

        if (hasInvalid) {
            throw new AuthTokenParseException("Unsupported signature algorithm");
        }
    }

    private static X509Certificate validateSigningCertificateExists(WebEidAuthToken token) throws AuthTokenParseException, CertificateDecodingException {
        if (isNullOrEmpty(token.getUnverifiedSigningCertificate())) {
            throw new AuthTokenParseException("'unverifiedSigningCertificate' field is missing, null or empty for format 'web-eid:1.1'");
        }
        return CertificateLoader.decodeCertificateFromBase64(token.getUnverifiedSigningCertificate());
    }

    private static void validateSameSubject(X509Certificate subjectCertificate, X509Certificate signingCertificate)
        throws AuthTokenParseException {
        if (!subjectAndSigningCertificateSubjectsMatch(
            subjectCertificate.getSubjectX500Principal(),
            signingCertificate.getSubjectX500Principal())) {
            throw new AuthTokenParseException("Signing certificate subject does not match authentication certificate subject");
        }
    }

    private static void validateSameIssuer(X509Certificate subjectCertificate, X509Certificate signingCertificate)
        throws AuthTokenParseException {
        byte[] subjectCertificateAuthorityKeyIdentifier = getAuthorityKeyIdentifier(subjectCertificate);
        byte[] signingCertificateAuthorityKeyIdentifier = getAuthorityKeyIdentifier(signingCertificate);

        if (subjectCertificateAuthorityKeyIdentifier.length == 0
            || signingCertificateAuthorityKeyIdentifier.length == 0
            || !Arrays.equals(subjectCertificateAuthorityKeyIdentifier, signingCertificateAuthorityKeyIdentifier)) {
            throw new AuthTokenParseException(
                "Signing certificate is not issued by the same issuing authority as the authentication certificate");
        }
    }

    private static void validateSigningCertificateValidity(X509Certificate signingCertificate)
            throws AuthTokenParseException {
        try {
            signingCertificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            throw new AuthTokenParseException("Signing certificate is not valid: " + e.getMessage(), e);
        }
    }

    private static void validateKeyUsage(X509Certificate signingCertificate)
            throws AuthTokenParseException {
        boolean[] keyUsage = signingCertificate.getKeyUsage();
        if (keyUsage == null || keyUsage.length <= KEY_USAGE_NON_REPUDIATION || !keyUsage[KEY_USAGE_NON_REPUDIATION]) {
            throw new AuthTokenParseException("Signing certificate key usage extension missing or does not contain non-repudiation bit required for digital signatures");
        }
    }

    private static boolean subjectAndSigningCertificateSubjectsMatch(
        X500Principal authenticationCertificateSubject,
        X500Principal signingCertificateSubject) {
        X500Name authName = X500Name.getInstance(RFC4519Style.INSTANCE, authenticationCertificateSubject.getEncoded());
        X500Name signName = X500Name.getInstance(RFC4519Style.INSTANCE, signingCertificateSubject.getEncoded());
        return authName.equals(signName);
    }

    private static byte[] getAuthorityKeyIdentifier(X509Certificate certificate) throws AuthTokenParseException {
        try {
            byte[] authorityKeyIdentifierExtension = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
            if (authorityKeyIdentifierExtension == null) {
                return new byte[0];
            }
            AuthorityKeyIdentifier authorityKeyIdentifier =
                AuthorityKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(authorityKeyIdentifierExtension));
            return authorityKeyIdentifier.getKeyIdentifier();
        } catch (Exception e) {
            throw new AuthTokenParseException("Failed to parse Authority Key Identifier", e);
        }
    }

    protected X509Certificate validateV1(WebEidAuthToken token, String currentChallengeNonce) throws AuthTokenException {
        return super.validate(token, currentChallengeNonce);
    }
}
