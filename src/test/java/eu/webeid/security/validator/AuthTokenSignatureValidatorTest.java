/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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
import eu.webeid.security.certificate.CertificateLoader;
import org.junit.jupiter.api.Test;
import eu.webeid.security.authtoken.WebEidAuthToken;

import java.net.URI;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThatCode;
import static eu.webeid.security.validator.AuthTokenSignatureTest.VALID_AUTH_TOKEN;
import static eu.webeid.security.validator.AuthTokenSignatureTest.VALID_CHALLENGE_NONCE;

class AuthTokenSignatureValidatorTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    static String VALID_RS256_AUTH_TOKEN = "{\"algorithm\":\"RS256\"," +
        "\"certificate\":\"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\"," +
        "\"issuerApp\":\"https://web-eid.eu/web-eid-app/releases/2.0.0+0\"," +
        "\"signature\":\"xsjXsQvVYXWcdV0YPhxLthJxtf0//R8p9WFFlYJGRARrl1ruyoAUwl0xeHgeZOKeJtwiCYCNWJzCG3VM3ydgt92bKhhk1u0JXIPVqvOkmDY72OCN4q73Y8iGSPVTgjk93TgquHlodf7YcqZNhutwNNf3oldHEWJD5zmkdwdpBFXgeOwTAdFwGljDQZbHr3h1Dr+apUDuloS0WuIzUuu8YXN2b8lh8FCTlF0G0DEjhHd/MGx8dbe3UTLHmD7K9DXv4zLJs6EF9i2v/C10SIBQDkPBSVPqMxCDPECjbEPi2+ds94eU7ThOhOQlFFtJ4KjQNTUa2crSixH7cYZF2rNNmA==\"," +
        "\"version\":\"web-eid:1\"}}";

    @Test
    void whenValidES384Signature_thenSucceeds() throws Exception {
        final AuthTokenSignatureValidator signatureValidator =
            new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        final WebEidAuthToken authToken = objectMapper.readValue(VALID_AUTH_TOKEN, WebEidAuthToken.class);
        final X509Certificate x509Certificate = CertificateLoader.decodeCertificateFromBase64(authToken.getCertificate());

        assertThatCode(() -> signatureValidator
            .validate("ES384", authToken.getSignature(), x509Certificate.getPublicKey(), VALID_CHALLENGE_NONCE, null))
            .doesNotThrowAnyException();
    }

    @Test
    void whenValidRS256Signature_thenSucceeds() throws Exception {
        final AuthTokenSignatureValidator signatureValidator =
            new AuthTokenSignatureValidator(URI.create("https://ria.ee"));

        final WebEidAuthToken authToken = objectMapper.readValue(VALID_RS256_AUTH_TOKEN, WebEidAuthToken.class);
        final X509Certificate x509Certificate = CertificateLoader.decodeCertificateFromBase64(authToken.getCertificate());

        assertThatCode(() -> signatureValidator
            .validate("RS256", authToken.getSignature(), x509Certificate.getPublicKey(), VALID_CHALLENGE_NONCE, null))
            .doesNotThrowAnyException();
    }

}
