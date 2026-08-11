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

import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.certificate.CertificateData;
import eu.webeid.security.exceptions.AuthTokenSignatureValidationException;
import eu.webeid.security.testutil.AuthTokenValidators;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.revocationcheck.CertificateRevocationChecker;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import java.security.cert.X509Certificate;
import java.util.List;

import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_AUTH_TOKEN;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_CHALLENGE_NONCE;
import static eu.webeid.security.testutil.DateMocker.mockDate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthTokenValidatorValidationOrderTest {

    private MockedStatic<DateAndTime.DefaultClock> mockedClock;

    @BeforeEach
    void setUp() {
        mockedClock = mockStatic(DateAndTime.DefaultClock.class);
        // Ensure that the certificates do not expire.
        mockDate("2021-07-23", mockedClock);
    }

    @AfterEach
    void tearDown() {
        mockedClock.close();
    }

    @Test
    void whenSignatureIsInvalid_thenRevocationCheckerIsNotInvoked() throws Exception {
        CertificateRevocationChecker checker = mock(CertificateRevocationChecker.class);
        AuthTokenValidator validator = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withCertificateRevocationChecker(checker)
            .build();
        WebEidAuthToken token = validator.parse(VALID_AUTH_TOKEN);

        assertThatThrownBy(() -> validator.validate(token, "invalidToken"))
            .isInstanceOf(AuthTokenSignatureValidationException.class);
        verify(checker, never()).validateCertificateNotRevoked(any(), any());
    }

    @Test
    void whenSignatureIsValid_thenRevocationCheckerIsInvoked() throws Exception {
        CertificateRevocationChecker checker = mock(CertificateRevocationChecker.class);
        when(checker.validateCertificateNotRevoked(any(), any())).thenReturn(List.of());
        AuthTokenValidator validator = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withCertificateRevocationChecker(checker)
            .build();
        WebEidAuthToken token = validator.parse(VALID_AUTH_TOKEN);

        assertThatCode(() -> validator.validate(token, VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
        ArgumentCaptor<X509Certificate> subjectCaptor = ArgumentCaptor.forClass(X509Certificate.class);
        verify(checker).validateCertificateNotRevoked(subjectCaptor.capture(), any());
        assertThat(CertificateData.getSubjectCN(subjectCaptor.getValue()).orElseThrow())
            .isEqualTo("JÕEORG\\,JAAK-KRISTJAN\\,38001085718");
    }
}
