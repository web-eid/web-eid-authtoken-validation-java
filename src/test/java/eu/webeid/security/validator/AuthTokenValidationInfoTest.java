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
import eu.webeid.security.testutil.AuthTokenValidators;
import eu.webeid.security.testutil.DateMocker;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.revocationcheck.CertificateRevocationChecker;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_AUTH_TOKEN;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_AUTH_TOKEN_TEST_DATE;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_CHALLENGE_NONCE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mockStatic;

class AuthTokenValidationInfoTest {

    private MockedStatic<DateAndTime.DefaultClock> mockedClock;

    @BeforeEach
    void setup() {
        mockedClock = mockStatic(DateAndTime.DefaultClock.class);
        DateMocker.mockDate(VALID_AUTH_TOKEN_TEST_DATE, mockedClock);
    }

    @AfterEach
    void tearDown() {
        mockedClock.close();
    }

    @Test
    void whenCustomRevocationCheckerProvidesInfo_thenValidationInfoContainsIt() throws Exception {
        final RevocationInfo expectedInfo = new RevocationInfo(
            URI.create("https://ocsp.example"),
            Map.of(RevocationInfo.KEY_OCSP_RESPONSE, "dummy-response")
        );
        final List<RevocationInfo> checkerResults = new ArrayList<>(List.of(expectedInfo));
        final CertificateRevocationChecker checker = (subjectCertificate, issuerCertificate) -> checkerResults;
        final AuthTokenValidator validator = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withCertificateRevocationChecker(checker)
            .build();

        final WebEidAuthToken token = validator.parse(VALID_AUTH_TOKEN);
        final ValidationInfo validationInfo = validator.validate(token, VALID_CHALLENGE_NONCE);

        checkerResults.clear();

        assertThat(validationInfo.revocationInfoList()).containsExactly(expectedInfo);
        assertThat(validationInfo.subjectCertificate()).isNotNull();
        assertThatThrownBy(() -> validationInfo.revocationInfoList().clear()).isInstanceOf(UnsupportedOperationException.class);
    }
}
