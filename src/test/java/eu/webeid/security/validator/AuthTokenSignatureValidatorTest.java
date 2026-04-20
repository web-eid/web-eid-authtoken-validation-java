// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.AuthTokenSignatureValidationException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.cert.X509Certificate;

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

}
