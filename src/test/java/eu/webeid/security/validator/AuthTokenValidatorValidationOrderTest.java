// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_AUTH_TOKEN_TEST_DATE;
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
        mockDate(VALID_AUTH_TOKEN_TEST_DATE, mockedClock);
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
