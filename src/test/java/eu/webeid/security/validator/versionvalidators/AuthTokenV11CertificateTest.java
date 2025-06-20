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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.CertificateDecodingException;
import eu.webeid.security.testutil.AbstractTestWithValidator;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.AuthTokenSignatureValidator;
import eu.webeid.security.validator.AuthTokenValidationConfiguration;
import eu.webeid.security.validator.certvalidators.SubjectCertificateValidatorBatch;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

import static eu.webeid.security.testutil.DateMocker.mockDate;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class AuthTokenV11CertificateTest extends AbstractTestWithValidator {

    private static final String V11_AUTH_TOKEN = "{\"algorithm\":\"ES384\"," +
        "\"unverifiedCertificate\":\"MIIEBDCCA2WgAwIBAgIQY5OGshxoPMFg+Wfc0gFEaTAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTIxMDcyMjEyNDMwOFoXDTI2MDcwOTIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQmwEKsJTjaMHSaZj19hb9EJaJlwbKc5VFzmlGMFSJVk4dDy+eUxa5KOA7tWXqzcmhh5SYdv+MxcaQKlKWLMa36pfgv20FpEDb03GCtLqjLTRZ7649PugAQ5EmAqIic29CjggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFPlp/ceABC52itoqppEmbf71TJz6MGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgDCAgybz0u3W+tGI+AX+PiI5CrE9ptEHO5eezR1Jo4j7iGaO0i39xTGUB+NSC7P6AQbyE/ywqJjA1a62jTLcS9GHAJCARxN4NO4eVdWU3zVohCXm8WN3DWA7XUcn9TZiLGQ29P4xfQZOXJi/z4PNRRsR4plvSNB3dfyBvZn31HhC7my8woi\"," +
        "\"unverifiedSigningCertificate\":\"X5C\"," +
        "\"supportedSignatureAlgorithms\":[{\"cryptoAlgorithm\":\"RSA\",\"hashFunction\":\"SHA-256\",\"paddingScheme\":\"PKCS1.5\"}]," +
        "\"appVersion\":\"https://web-eid.eu/web-eid-mobile-app/releases/v1.0.0\"," +
        "\"signature\":\"xsjXsQvVYXWcdV0YPhxLthJxtf0//R8p9WFFlYJGRARrl1ruyoAUwl0xeHgeZOKeJtwiCYCNWJzCG3VM3ydgt92bKhhk1u0JXIPVqvOkmDY72OCN4q73Y8iGSPVTgjk93TgquHlodf7YcqZNhutwNNf3oldHEWJD5zmkdwdpBFXgeOwTAdFwGljDQZbHr3h1Dr+apUDuloS0WuIzUuu8YXN2b8lh8FCTlF0G0DEjhHd/MGx8dbe3UTLHmD7K9DXv4zLJs6EF9i2v/C10SIBQDkPBSVPqMxCDPECjbEPi2+ds94eU7ThOhOQlFFtJ4KjQNTUa2crSixH7cYZF2rNNmA==\"," +
        "\"format\":\"web-eid:1.1\"}";

    private static final String DIFFERENT_CERT = "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";

    private MockedStatic<DateAndTime.DefaultClock> mockedClock;
    private static final ObjectReader OBJECT_READER = new ObjectMapper().readerFor(WebEidAuthToken.class);
    private SubjectCertificateValidatorBatch scvb;
    private Set<TrustAnchor> trustedCACertificateAnchors;
    private CertStore trustedCACertificateCertStore;
    private AuthTokenSignatureValidator signatureValidator;
    private AuthTokenValidationConfiguration configuration;
    private OcspClient ocspClient;
    private OcspServiceProvider ocspServiceProvider;

    @Override
    @BeforeEach
    protected void setup() {
        super.setup();
        mockedClock = mockStatic(DateAndTime.DefaultClock.class);
        // Ensure that the certificates do not expire.
        mockDate("2021-08-01", mockedClock);
        scvb = mock(SubjectCertificateValidatorBatch.class);
        trustedCACertificateAnchors = Collections.emptySet();
        trustedCACertificateCertStore = mock(CertStore.class);
        signatureValidator = mock(AuthTokenSignatureValidator.class);
        configuration = mock(AuthTokenValidationConfiguration.class);
        ocspClient = mock(OcspClient.class);
        ocspServiceProvider = mock(OcspServiceProvider.class);
    }

    @AfterEach
    void tearDown() {
        mockedClock.close();
    }

    @Test
    void whenValidV11Token_thenValidationSucceeds() {
        mockDate("2023-10-01", mockedClock);
        assertThatCode(() -> validator
            .validate(validV11AuthToken, VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
    }

    @Test
    void whenV11SigningCertificateFieldIsMissing_thenValidationFails() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = (ObjectNode) mapper.readTree(V11_AUTH_TOKEN);
        node.remove("unverifiedSigningCertificate");
        WebEidAuthToken token = OBJECT_READER.readValue(node.toString());

        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        doReturn(mock(X509Certificate.class)).when(spyValidator).validateV1(any(), any());

        assertThatThrownBy(() -> spyValidator.validate(token, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("'unverifiedSigningCertificate' field is missing, null or empty for format 'web-eid:1.1'");
    }

    @Test
    void whenV11SigningCertificateIsNotBase64_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        X509Certificate mockSubjectCert = CertificateLoader.decodeCertificateFromBase64(OBJECT_READER.readValue(V11_AUTH_TOKEN, WebEidAuthToken.class).getUnverifiedCertificate());
        doReturn(mockSubjectCert).when(spyValidator).validateV1(any(), any());
        WebEidAuthToken token = getWebEidAuthToken("This is not a certificate");

        assertThatThrownBy(() -> spyValidator
            .validate(token, VALID_CHALLENGE_NONCE))
            .isInstanceOf(CertificateDecodingException.class)
            .cause()
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Illegal base64 character");
    }

    @Test
    void whenV11SigningCertificateIsNotACertificate_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        X509Certificate mockSubjectCert = CertificateLoader.decodeCertificateFromBase64(OBJECT_READER.readValue(V11_AUTH_TOKEN, WebEidAuthToken.class).getUnverifiedCertificate());
        doReturn(mockSubjectCert).when(spyValidator).validateV1(any(), any());
        WebEidAuthToken token = getWebEidAuthToken("VGhpcyBpcyBub3QgYSBjZXJ0aWZpY2F0ZQ");

        assertThatThrownBy(() -> spyValidator.validate(token, VALID_CHALLENGE_NONCE))
            .isInstanceOf(CertificateDecodingException.class)
            .cause()
            .isInstanceOf(CertificateException.class)
            .hasMessage("Could not parse certificate: java.io.IOException: Empty input");
    }

    @Test
    void whenV11SigningCertificateSubjectDoesNotMatch_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        X509Certificate mockSubjectCert = CertificateLoader.decodeCertificateFromBase64(OBJECT_READER.readValue(V11_AUTH_TOKEN, WebEidAuthToken.class).getUnverifiedCertificate());
        doReturn(mockSubjectCert).when(spyValidator).validateV1(any(), any());
        WebEidAuthToken token = getWebEidAuthToken(DIFFERENT_CERT);

        assertThatThrownBy(() -> spyValidator.validate(token, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("Signing certificate subject does not match authentication certificate subject");
    }

    @Test
    void whenV11SigningCertificateNotIssuedBySameAuthority_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        WebEidAuthToken parsedToken = OBJECT_READER.readValue(V11_AUTH_TOKEN, WebEidAuthToken.class);
        X509Certificate realSubjectCert = CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate());
        doReturn(realSubjectCert).when(spyValidator).validateV1(any(), any());

        X509Certificate mockSigningCert = mock(X509Certificate.class);
        when(mockSigningCert.getSubjectX500Principal()).thenReturn(realSubjectCert.getSubjectX500Principal());

        byte[] realAki = realSubjectCert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        byte[] differentAki = realAki.clone();
        if (differentAki.length > 0) {
            differentAki[differentAki.length - 1] ^= (byte) 0xFF;
        }
        when(mockSigningCert.getExtensionValue(Extension.authorityKeyIdentifier.getId())).thenReturn(differentAki);

        try (MockedStatic<CertificateLoader> mocked = mockStatic(CertificateLoader.class)) {
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate()))
                .thenReturn(realSubjectCert);
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedSigningCertificate()))
                .thenReturn(mockSigningCert);

            assertThatThrownBy(() -> spyValidator.validate(parsedToken, VALID_CHALLENGE_NONCE))
                .isInstanceOf(AuthTokenParseException.class)
                .hasMessage("Signing certificate is not issued by the same issuing authority as the authentication certificate");
        }
    }

    @Test
    void whenV11SigningCertificateHasNoAuthorityKeyIdentifier_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        WebEidAuthToken parsedToken = OBJECT_READER.readValue(V11_AUTH_TOKEN, WebEidAuthToken.class);
        X509Certificate realSubjectCert = CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate());
        doReturn(realSubjectCert).when(spyValidator).validateV1(any(), any());

        X509Certificate mockSigningCert = mock(X509Certificate.class);
        when(mockSigningCert.getSubjectX500Principal()).thenReturn(realSubjectCert.getSubjectX500Principal());
        when(mockSigningCert.getExtensionValue(Extension.authorityKeyIdentifier.getId())).thenReturn(null);

        try (MockedStatic<CertificateLoader> mocked = mockStatic(CertificateLoader.class)) {
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate()))
                .thenReturn(realSubjectCert);
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedSigningCertificate()))
                .thenReturn(mockSigningCert);

            assertThatThrownBy(() -> spyValidator.validate(parsedToken, VALID_CHALLENGE_NONCE))
                .isInstanceOf(AuthTokenParseException.class)
                .hasMessage("Signing certificate is not issued by the same issuing authority as the authentication certificate");
        }
    }

    @Test
    void whenV11SigningCertificateNotSuitableForSigning_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        WebEidAuthToken parsedToken = OBJECT_READER.readValue(V11_AUTH_TOKEN, WebEidAuthToken.class);
        X509Certificate realSubjectCert = CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate());
        doReturn(realSubjectCert).when(spyValidator).validateV1(any(), any());

        X509Certificate signingCert = mock(X509Certificate.class);
        when(signingCert.getSubjectX500Principal()).thenReturn(realSubjectCert.getSubjectX500Principal());
        when(signingCert.getIssuerX500Principal()).thenReturn(realSubjectCert.getIssuerX500Principal());
        when(signingCert.getExtensionValue(Extension.authorityKeyIdentifier.getId()))
            .thenReturn(realSubjectCert.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
        when(signingCert.getKeyUsage()).thenReturn(new boolean[]{true, false});

        try (MockedStatic<CertificateLoader> mocked = mockStatic(CertificateLoader.class)) {
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate()))
                .thenReturn(realSubjectCert);
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedSigningCertificate()))
                .thenReturn(signingCert);

            assertThatThrownBy(() -> spyValidator.validate(parsedToken, VALID_CHALLENGE_NONCE))
                .isInstanceOf(AuthTokenParseException.class)
                .hasMessage("Signing certificate key usage extension missing or does not contain non-repudiation bit required for digital signatures");
        }
    }

    private AuthTokenVersion11Validator spyAuthTokenVersion11Validator() {
        return Mockito.spy(new AuthTokenVersion11Validator(
            scvb,
            trustedCACertificateAnchors,
            trustedCACertificateCertStore,
            signatureValidator,
            configuration,
            ocspClient,
            ocspServiceProvider
        ));
    }

    private static WebEidAuthToken getWebEidAuthToken(String cert) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = (ObjectNode) mapper.readTree(V11_AUTH_TOKEN);
        node.put("unverifiedSigningCertificate", cert);
        return OBJECT_READER.readValue(node.toString());
    }

}
