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
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.validator.AuthTokenSignatureValidator;
import eu.webeid.security.validator.AuthTokenValidationConfiguration;
import eu.webeid.security.validator.certvalidators.SubjectCertificateValidatorBatch;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class AuthTokenVersion11ValidatorTest {

    private AuthTokenVersion11Validator validator;

    @BeforeEach
    void setUp() {
        SubjectCertificateValidatorBatch scvb = mock(SubjectCertificateValidatorBatch.class);
        Set<TrustAnchor> trustAnchors = Collections.emptySet();
        CertStore certStore = mock(CertStore.class);
        AuthTokenSignatureValidator signatureValidator = mock(AuthTokenSignatureValidator.class);
        AuthTokenValidationConfiguration config = mock(AuthTokenValidationConfiguration.class);
        OcspClient ocspClient = mock(OcspClient.class);
        OcspServiceProvider ocspServiceProvider = mock(OcspServiceProvider.class);

        validator = new AuthTokenVersion11Validator(
            scvb,
            trustAnchors,
            certStore,
            signatureValidator,
            config,
            ocspClient,
            ocspServiceProvider
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {"web-eid:1.1", "web-eid:1.1.0", "web-eid:1.10"})
    void whenFormatIsV11OrPrefixedVariant_thenSupportsReturnsTrue(String format) {
        assertThat(validator.supports(format)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"web-eid:1", "web-eid:1.0", "web-eid:2", "webauthn:1.1"})
    void whenFormatIsNullEmptyOrNotV11_thenSupportsReturnsFalse(String format) {
        assertThat(validator.supports(format)).isFalse();
    }

    @Test
    void whenUnverifiedSigningCertificateMissing_thenValidationFails() throws Exception {
        WebEidAuthToken token = mock(WebEidAuthToken.class);
        when(token.getFormat()).thenReturn("web-eid:1.1");
        when(token.getUnverifiedSigningCertificate()).thenReturn(null);

        AuthTokenVersion11Validator spyValidator = Mockito.spy(validator);
        doReturn(mock(X509Certificate.class)).when(spyValidator).validateV1(any(), any());

        assertThatThrownBy(() -> spyValidator.validate(token, "nonce"))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessage("'unverifiedSigningCertificate' field is missing, null or empty for format 'web-eid:1.1'");
    }

    @Test
    void whenSupportedSignatureAlgorithmsMissing_thenValidationFails() throws Exception {
        WebEidAuthToken token = mock(WebEidAuthToken.class);
        when(token.getFormat()).thenReturn("web-eid:1.1");
        when(token.getUnverifiedSigningCertificate()).thenReturn("abc");
        when(token.getSupportedSignatureAlgorithms()).thenReturn(null);

        AuthTokenVersion11Validator spyValidator = Mockito.spy(validator);
        doReturn(mock(X509Certificate.class)).when(spyValidator).validateV1(any(), any());

        try (MockedStatic<CertificateLoader> mocked = mockStatic(CertificateLoader.class)) {
            mocked.when(() -> CertificateLoader.decodeCertificateFromBase64("abc"))
                .thenReturn(mock(X509Certificate.class));

            assertThatThrownBy(() -> spyValidator.validate(token, "nonce"))
                .isInstanceOf(AuthTokenParseException.class)
                .hasMessage("'supportedSignatureAlgorithms' field is missing");
        }
    }
}
