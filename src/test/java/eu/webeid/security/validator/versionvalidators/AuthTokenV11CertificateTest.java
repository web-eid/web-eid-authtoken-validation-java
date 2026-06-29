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

import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.exceptions.CertificateDecodingException;
import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotTrustedException;
import eu.webeid.security.exceptions.CertificateNotYetValidException;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;

import static eu.webeid.security.testutil.DateMocker.mockDate;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class AuthTokenV11CertificateTest extends AbstractTestWithValidator {

    private static final String DIFFERENT_CERT = "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";

    private MockedStatic<DateAndTime.DefaultClock> mockedClock;
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
        WebEidAuthToken token = validator.parse(VALID_V11_AUTH_TOKEN);
        token.setUnverifiedSigningCertificates(null);

        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        doReturn(mock(X509Certificate.class)).when(spyValidator).validateV1(any(), any(), any());

        assertThatThrownBy(() -> spyValidator.validate(token, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("'unverifiedSigningCertificates' field is missing, null or empty for format 'web-eid:1.1'");
    }

    @Test
    void whenV11SigningCertificateIsNotBase64_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        X509Certificate mockSubjectCert = CertificateLoader.decodeCertificateFromBase64(validV11AuthToken.getUnverifiedCertificate());
        doReturn(mockSubjectCert).when(spyValidator).validateV1(any(), any(), any());
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
        X509Certificate mockSubjectCert = CertificateLoader.decodeCertificateFromBase64(validV11AuthToken.getUnverifiedCertificate());
        doReturn(mockSubjectCert).when(spyValidator).validateV1(any(), any(), any());
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
        X509Certificate mockSubjectCert = CertificateLoader.decodeCertificateFromBase64(validV11AuthToken.getUnverifiedCertificate());
        doReturn(mockSubjectCert).when(spyValidator).validateV1(any(), any(), any());
        WebEidAuthToken token = getWebEidAuthToken(DIFFERENT_CERT);

        assertThatThrownBy(() -> spyValidator.validate(token, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("Signing certificate subject does not match authentication certificate subject");
    }

    @Test
    void whenV11SigningCertificateNotIssuedBySameAuthority_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        WebEidAuthToken parsedToken = validator.parse(VALID_V11_AUTH_TOKEN);
        X509Certificate realSubjectCert = CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate());
        doReturn(realSubjectCert).when(spyValidator).validateV1(any(), any(), any());

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
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedSigningCertificates().getFirst().getCertificate()))
                .thenReturn(mockSigningCert);

            assertThatThrownBy(() -> spyValidator.validate(parsedToken, VALID_CHALLENGE_NONCE))
                .isInstanceOf(AuthTokenParseException.class)
                .hasMessage("Signing certificate is not issued by the same issuing authority as the authentication certificate");
        }
    }

    @Test
    void whenV11SigningCertificateHasNoAuthorityKeyIdentifier_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        WebEidAuthToken parsedToken = validator.parse(VALID_V11_AUTH_TOKEN);
        X509Certificate realSubjectCert = CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate());
        doReturn(realSubjectCert).when(spyValidator).validateV1(any(), any(), any());

        X509Certificate mockSigningCert = mock(X509Certificate.class);
        when(mockSigningCert.getSubjectX500Principal()).thenReturn(realSubjectCert.getSubjectX500Principal());
        when(mockSigningCert.getExtensionValue(Extension.authorityKeyIdentifier.getId())).thenReturn(null);

        try (MockedStatic<CertificateLoader> mocked = mockStatic(CertificateLoader.class)) {
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate()))
                .thenReturn(realSubjectCert);
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedSigningCertificates().getFirst().getCertificate()))
                .thenReturn(mockSigningCert);

            assertThatThrownBy(() -> spyValidator.validate(parsedToken, VALID_CHALLENGE_NONCE))
                .isInstanceOf(AuthTokenParseException.class)
                .hasMessage("Signing certificate is not issued by the same issuing authority as the authentication certificate");
        }
    }

    @Test
    void whenV11SigningCertificateNotSuitableForSigning_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        WebEidAuthToken parsedToken = validator.parse(VALID_V11_AUTH_TOKEN);
        X509Certificate realSubjectCert = CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate());
        doReturn(realSubjectCert).when(spyValidator).validateV1(any(), any(), any());

        X509Certificate signingCert = mock(X509Certificate.class);
        when(signingCert.getSubjectX500Principal()).thenReturn(realSubjectCert.getSubjectX500Principal());
        when(signingCert.getIssuerX500Principal()).thenReturn(realSubjectCert.getIssuerX500Principal());
        when(signingCert.getExtensionValue(Extension.authorityKeyIdentifier.getId()))
            .thenReturn(realSubjectCert.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
        when(signingCert.getKeyUsage()).thenReturn(new boolean[]{true, false});

        try (MockedStatic<CertificateLoader> mocked = mockStatic(CertificateLoader.class)) {
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedCertificate()))
                .thenReturn(realSubjectCert);
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64(parsedToken.getUnverifiedSigningCertificates().getFirst().getCertificate()))
                .thenReturn(signingCert);

            assertThatThrownBy(() -> spyValidator.validate(parsedToken, VALID_CHALLENGE_NONCE))
                .isInstanceOf(AuthTokenParseException.class)
                .hasMessage("Signing certificate key usage extension missing or does not contain non-repudiation bit required for digital signatures");
        }
    }

    @Test
    void whenValidV11TokenWithUnverifiedIntermediateCertificates_thenValidationSucceeds() throws Exception {
        mockDate("2023-10-01", mockedClock);

        validV11AuthToken.setUnverifiedIntermediateCertificates(Arrays.asList(esteid2018CaCertificateInBase64()));

        assertThatCode(() -> validator.validate(validV11AuthToken, VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
    }

    @Test
    void whenUnverifiedSigningCertificatesAbsentButUnverifiedIntermediateCertificatesPresent_thenValidationSucceeds() throws Exception {
        mockDate("2023-10-01", mockedClock);

        validV11AuthToken.setUnverifiedSigningCertificates(null);
        validV11AuthToken.setUnverifiedIntermediateCertificates(Arrays.asList(esteid2018CaCertificateInBase64()));

        assertThatCode(() -> validator.validate(validV11AuthToken, VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
    }

    @Test
    void whenValidV11TokenWithSigningIntermediateCertificates_thenValidationSucceeds() throws Exception {
        mockDate("2023-10-01", mockedClock);

        validV11AuthToken.getUnverifiedSigningCertificates().get(0)
            .setIntermediateCertificates(Arrays.asList(esteid2018CaCertificateInBase64()));

        assertThatCode(() -> validator.validate(validV11AuthToken, VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
    }

    @Test
    void whenUnverifiedIntermediateCertificatesEmpty_thenValidationFails() {
        validV11AuthToken.setUnverifiedIntermediateCertificates(Collections.emptyList());

        assertThatThrownBy(() -> validator.validate(validV11AuthToken, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("'unverifiedIntermediateCertificates' must not be empty for format 'web-eid:1.1'");
    }

    @Test
    void whenUnverifiedIntermediateCertificateContainsEmptyEntry_thenValidationFails() {
        validV11AuthToken.setUnverifiedIntermediateCertificates(Arrays.asList(""));

        assertThatThrownBy(() -> validator.validate(validV11AuthToken, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("'unverifiedIntermediateCertificates' must not contain null or empty entries for format 'web-eid:1.1'");
    }

    @Test
    void whenUnverifiedIntermediateCertificateIsNotBase64_thenValidationFails() {
        validV11AuthToken.setUnverifiedIntermediateCertificates(Arrays.asList("This is not a certificate"));

        assertThatThrownBy(() -> validator.validate(validV11AuthToken, VALID_CHALLENGE_NONCE))
            .isInstanceOf(CertificateDecodingException.class);
    }

    @Test
    void whenV11SigningCertificateNotTrusted_thenValidationFails() throws Exception {
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        X509Certificate realSubjectCert = CertificateLoader.decodeCertificateFromBase64(validV11AuthToken.getUnverifiedCertificate());
        doReturn(realSubjectCert).when(spyValidator).validateV1(any(), any(), any());

        try (MockedStatic<CertificateValidator> mocked = mockStatic(CertificateValidator.class)) {
            mocked.when(() -> CertificateValidator.validateIsSignedByTrustedCA(any(), any(), any(), anyList(), any()))
                .thenThrow(new CertificateNotTrustedException(realSubjectCert, new RuntimeException("not trusted")));

            assertThatThrownBy(() -> spyValidator.validate(validV11AuthToken, VALID_CHALLENGE_NONCE))
                .isInstanceOf(AuthTokenParseException.class)
                .hasMessageContaining("Signing certificate validation failed")
                .hasCauseInstanceOf(CertificateNotTrustedException.class);
        }
    }

    @Test
    void whenV11SigningCertificateExpired_thenValidationFails() throws Exception {
        // Move the clock past the signing certificate's validity window so that the real
        // CertificateValidator.validateIsSignedByTrustedCA() rejects it as expired.
        mockDate("2099-01-01", mockedClock);
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        X509Certificate realSubjectCert = CertificateLoader.decodeCertificateFromBase64(validV11AuthToken.getUnverifiedCertificate());
        doReturn(realSubjectCert).when(spyValidator).validateV1(any(), any(), any());

        assertThatThrownBy(() -> spyValidator.validate(validV11AuthToken, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessageContaining("Signing certificate validation failed")
            .hasCauseInstanceOf(CertificateExpiredException.class);
    }

    @Test
    void whenV11SigningCertificateNotYetValid_thenValidationFails() throws Exception {
        // Move the clock before the signing certificate's validity window so that the real
        // CertificateValidator.validateIsSignedByTrustedCA() rejects it as not yet valid.
        mockDate("2000-01-01", mockedClock);
        AuthTokenVersion11Validator spyValidator = spyAuthTokenVersion11Validator();
        X509Certificate realSubjectCert = CertificateLoader.decodeCertificateFromBase64(validV11AuthToken.getUnverifiedCertificate());
        doReturn(realSubjectCert).when(spyValidator).validateV1(any(), any(), any());

        assertThatThrownBy(() -> spyValidator.validate(validV11AuthToken, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessageContaining("Signing certificate validation failed")
            .hasCauseInstanceOf(CertificateNotYetValidException.class);
    }

    private static String esteid2018CaCertificateInBase64() throws Exception {
        X509Certificate caCertificate = CertificateLoader.loadCertificatesFromResources("TEST_of_ESTEID2018.cer")[0];
        return Base64.getEncoder().encodeToString(caCertificate.getEncoded());
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

    private WebEidAuthToken getWebEidAuthToken(String cert) throws AuthTokenException {
        WebEidAuthToken token = validator.parse(VALID_V11_AUTH_TOKEN);
        token.getUnverifiedSigningCertificates().get(0).setCertificate(cert);
        return token;
    }

}
