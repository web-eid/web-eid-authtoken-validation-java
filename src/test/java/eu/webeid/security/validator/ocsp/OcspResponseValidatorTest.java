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

package eu.webeid.security.validator.ocsp;

import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static eu.webeid.security.validator.AuthTokenValidatorBuilderTest.CONFIGURATION;
import static eu.webeid.security.validator.ocsp.OcspResponseValidator.validateCertificateStatusUpdateTime;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OcspResponseValidatorTest {

    private static final Duration TIME_SKEW = CONFIGURATION.getAllowedOcspResponseTimeSkew();
    private static final Duration THIS_UPDATE_AGE = CONFIGURATION.getMaxOcspResponseThisUpdateAge();

    @Test
    void whenThisAndNextUpdateWithinSkew_thenValidationSucceeds() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var thisUpdateWithinAgeLimit = getThisUpdateWithinAgeLimit(now);
        var nextUpdateWithinAgeLimit = Date.from(now.minus(THIS_UPDATE_AGE.minusSeconds(2)));
        when(mockResponse.getThisUpdate()).thenReturn(thisUpdateWithinAgeLimit);
        when(mockResponse.getNextUpdate()).thenReturn(nextUpdateWithinAgeLimit);
        assertThatCode(() -> validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, null))
            .doesNotThrowAnyException();
    }

    @Test
    void whenNextUpdateBeforeThisUpdate_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var thisUpdateWithinAgeLimit = getThisUpdateWithinAgeLimit(now);
        var beforeThisUpdate = new Date(thisUpdateWithinAgeLimit.getTime() - 1000);
        when(mockResponse.getThisUpdate()).thenReturn(thisUpdateWithinAgeLimit);
        when(mockResponse.getNextUpdate()).thenReturn(beforeThisUpdate);
        OcspValidationInfo ocspValidationInfo = mock(OcspValidationInfo.class);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, ocspValidationInfo))
            .withMessageStartingWith("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "nextUpdate '" + beforeThisUpdate.toInstant() + "' is before thisUpdate '" + thisUpdateWithinAgeLimit.toInstant() + "'")
            .satisfies(e -> assertThat(e.getOcspValidationInfo()).isNotNull());
    }

    @Test
    void whenThisUpdateHalfHourBeforeNow_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var halfHourBeforeNow = Date.from(now.minus(30, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(halfHourBeforeNow);
        OcspValidationInfo ocspValidationInfo = mock(OcspValidationInfo.class);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, ocspValidationInfo))
            .withMessageStartingWith("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "thisUpdate '" + halfHourBeforeNow.toInstant() + "' is too old, minimum time allowed: ")
            .satisfies(e -> assertThat(e.getOcspValidationInfo()).isNotNull());
    }

    @Test
    void whenThisUpdateHalfHourAfterNow_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var halfHourAfterNow = Date.from(now.plus(30, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(halfHourAfterNow);
        OcspValidationInfo ocspValidationInfo = mock(OcspValidationInfo.class);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, ocspValidationInfo))
            .withMessageStartingWith("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "thisUpdate '" + halfHourAfterNow.toInstant() + "' is too far in the future, latest allowed: ")
            .satisfies(e -> assertThat(e.getOcspValidationInfo()).isNotNull());
    }

    @Test
    void whenNextUpdateHalfHourBeforeNow_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var thisUpdateWithinAgeLimit = getThisUpdateWithinAgeLimit(now);
        var halfHourBeforeNow = Date.from(now.minus(30, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(thisUpdateWithinAgeLimit);
        when(mockResponse.getNextUpdate()).thenReturn(halfHourBeforeNow);
        OcspValidationInfo ocspValidationInfo = mock(OcspValidationInfo.class);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, TIME_SKEW, THIS_UPDATE_AGE, ocspValidationInfo))
            .withMessage("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "nextUpdate '" + halfHourBeforeNow.toInstant() + "' is in the past")
            .satisfies(e -> assertThat(e.getOcspValidationInfo()).isNotNull());
    }

    private static Date getThisUpdateWithinAgeLimit(Instant now) {
        return Date.from(now.minus(THIS_UPDATE_AGE.minusSeconds(1)));
    }

}
