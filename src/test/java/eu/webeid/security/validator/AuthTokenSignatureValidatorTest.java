// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.AuthTokenSignatureValidationException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_AUTH_TOKEN;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_CHALLENGE_NONCE;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_RS256_AUTH_TOKEN;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthTokenSignatureValidatorTest {

    private static final ObjectReader OBJECT_READER = new ObjectMapper().readerFor(WebEidAuthToken.class);

    @Test
    void whenSignatureIsNotBase64_thenThrowsParseExceptionWithCause() throws Exception {
        final WebEidAuthToken token = OBJECT_READER.readValue(VALID_RS256_AUTH_TOKEN);
        final X509Certificate certificate = CertificateLoader.decodeCertificateFromBase64(token.unverifiedCertificate());
        final AuthTokenSignatureValidator validator = new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        assertThatThrownBy(() -> validator.validate("RS256", "!!", certificate.getPublicKey(), VALID_CHALLENGE_NONCE))
                .isInstanceOf(AuthTokenParseException.class)
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void whenRsaSignatureHasInvalidLength_thenThrowsSignatureValidationExceptionWithCause() throws Exception {
        final WebEidAuthToken token = OBJECT_READER.readValue(VALID_RS256_AUTH_TOKEN);
        final X509Certificate certificate = CertificateLoader.decodeCertificateFromBase64(token.unverifiedCertificate());
        final AuthTokenSignatureValidator validator = new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        assertThatThrownBy(() -> validator.validate("RS256", "AA==", certificate.getPublicKey(), VALID_CHALLENGE_NONCE))
                .isInstanceOf(AuthTokenSignatureValidationException.class)
                .hasCauseInstanceOf(SignatureException.class);
    }

    @Test
    void whenValidES384Signature_thenSucceeds() throws Exception {
        final AuthTokenSignatureValidator signatureValidator =
            new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        final WebEidAuthToken authToken = OBJECT_READER.readValue(VALID_AUTH_TOKEN);
        final X509Certificate x509Certificate = CertificateLoader.decodeCertificateFromBase64(authToken.unverifiedCertificate());

        assertThatCode(() -> signatureValidator
            .validate("ES384", authToken.signature(), x509Certificate.getPublicKey(), VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
    }

    @Test
    void whenValidRS256Signature_thenSucceeds() throws Exception {
        final AuthTokenSignatureValidator signatureValidator =
            new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        final WebEidAuthToken authToken = OBJECT_READER.readValue(VALID_RS256_AUTH_TOKEN);
        final X509Certificate x509Certificate = CertificateLoader.decodeCertificateFromBase64(authToken.unverifiedCertificate());

        assertThatCode(() -> signatureValidator
            .validate("RS256", authToken.signature(), x509Certificate.getPublicKey(), VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
    }

    @Test
    void whenRsaKeyIsTooShortForAlgorithm_thenThrowsAuthTokenSignatureValidationException() throws Exception {
        final AuthTokenSignatureValidator signatureValidator =
            new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        final PublicKey weakPublicKey = keyPairGenerator.generateKeyPair().getPublic();

        final WebEidAuthToken authToken = OBJECT_READER.readValue(VALID_RS256_AUTH_TOKEN);

        // The public key comes from the unverified certificate of the token, so a key that JJWT refuses
        // to use must fail with a checked AuthTokenException, not with an unchecked JJWT exception.
        assertThatThrownBy(() -> signatureValidator
            .validate("RS256", authToken.signature(), weakPublicKey, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenSignatureValidationException.class);
    }

    @Test
    void whenEcKeyDoesNotMatchAlgorithm_thenThrowsAuthTokenSignatureValidationException() throws Exception {
        final AuthTokenSignatureValidator signatureValidator =
            new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        final PublicKey p256PublicKey = keyPairGenerator.generateKeyPair().getPublic();

        final WebEidAuthToken authToken = OBJECT_READER.readValue(VALID_AUTH_TOKEN);

        // ES512 requires a P-521 key, so JJWT rejects the P-256 key of the unverified certificate.
        assertThatThrownBy(() -> signatureValidator
            .validate("ES512", authToken.signature(), p256PublicKey, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenException.class);
    }

}
