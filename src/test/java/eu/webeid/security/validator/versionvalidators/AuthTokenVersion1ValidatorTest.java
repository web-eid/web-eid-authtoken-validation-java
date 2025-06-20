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
import eu.webeid.security.exceptions.AuthTokenParseException;
import eu.webeid.security.validator.AuthTokenSignatureValidator;
import eu.webeid.security.validator.AuthTokenValidationConfiguration;
import eu.webeid.security.validator.certvalidators.SubjectCertificateValidatorBatch;
import eu.webeid.security.validator.ocsp.OcspClient;
import eu.webeid.security.validator.ocsp.OcspServiceProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.cert.CertStore;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthTokenVersion1ValidatorTest {

    private final SubjectCertificateValidatorBatch scvb = mock(SubjectCertificateValidatorBatch.class);
    private final AuthTokenSignatureValidator signatureValidator = mock(AuthTokenSignatureValidator.class);
    private final AuthTokenValidationConfiguration config = mock(AuthTokenValidationConfiguration.class);

    private final AuthTokenVersion1Validator validator = new AuthTokenVersion1Validator(
        scvb,
        Set.of(),
        mock(CertStore.class),
        signatureValidator,
        config,
        mock(OcspClient.class),
        mock(OcspServiceProvider.class)
    );

    @ParameterizedTest
    @ValueSource(strings = {"web-eid:1", "web-eid:1.0", "web-eid:1.1", "web-eid:1.10"})
    void whenFormatIsAnyMajorV1Variant_thenSupportsReturnsTrue(String format) {
        assertThat(validator.supports(format)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"web-eid", "web-eid:0.9", "web-eid:2", "webauthn:1"})
    void whenFormatIsNullEmptyOrNotV1_thenSupportsReturnsFalse(String format) {
        assertThat(validator.supports(format)).isFalse();
    }

    @Test
    void whenUnverifiedCertificateMissing_thenValidationFails() {
        WebEidAuthToken token = mock(WebEidAuthToken.class);
        when(token.getFormat()).thenReturn("web-eid:1");
        when(token.getUnverifiedCertificate()).thenReturn(null);

        assertThatThrownBy(() -> validator.validate(token, "nonce"))
            .isInstanceOf(AuthTokenParseException.class)
            .hasMessageContaining("'unverifiedCertificate' field is missing");
    }
}
