/*
 * Copyright (c) 2020-2024 Estonian Information System Authority
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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static eu.webeid.security.validator.ocsp.OcspResponseValidator.ALLOWED_TIME_SKEW_MILLIS;
import static eu.webeid.security.validator.ocsp.OcspResponseValidator.toUtcString;
import static eu.webeid.security.validator.ocsp.OcspResponseValidator.validateCertificateStatusUpdateTime;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OcspResponseValidatorTest {

    @Test
    void whenThisAndNextUpdateWithinSkew_thenValidationSucceeds() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var allowedSkewBeforeNow = Date.from(now.minus(ALLOWED_TIME_SKEW_MILLIS + 1000, ChronoUnit.MILLIS));
        var allowedSkewAfterNow = Date.from(now.minus(ALLOWED_TIME_SKEW_MILLIS - 1000, ChronoUnit.MILLIS));
        when(mockResponse.getThisUpdate()).thenReturn(allowedSkewBeforeNow);
        when(mockResponse.getNextUpdate()).thenReturn(allowedSkewAfterNow);
        assertThatCode(() -> validateCertificateStatusUpdateTime(mockResponse))
            .doesNotThrowAnyException();
    }

    @Test
    void whenThisUpdateHalfHourBeforeNow_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var halfHourBeforeNow = Date.from(now.minus(30, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(halfHourBeforeNow);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse))
            .withMessage("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + getNotAllowedBeforeAndAfter()
                + "thisUpdate: " + toUtcString(halfHourBeforeNow) + ", "
                + "nextUpdate: null");
    }

    @Test
    void whenThisUpdateHalfHourAfterNow_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var halfHourAfterNow = Date.from(now.plus(30, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(halfHourAfterNow);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse))
            .withMessage("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + getNotAllowedBeforeAndAfter()
                + "thisUpdate: " + toUtcString(halfHourAfterNow) + ", "
                + "nextUpdate: null");
    }

    @Test
    void whenNextUpdateHalfHourBeforeNow_thenThrows() {
        final SingleResp mockResponse = mock(SingleResp.class);
        var now = Instant.now();
        var allowedSkewBeforeNow = Date.from(now.minus(ALLOWED_TIME_SKEW_MILLIS + 1000, ChronoUnit.MILLIS));
        var halfHourBeforeNow = Date.from(now.minus(30, ChronoUnit.MINUTES));
        when(mockResponse.getThisUpdate()).thenReturn(allowedSkewBeforeNow);
        when(mockResponse.getNextUpdate()).thenReturn(halfHourBeforeNow);
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse))
            .withMessage("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + getNotAllowedBeforeAndAfter()
                + "thisUpdate: " + toUtcString(allowedSkewBeforeNow) + ", "
                + "nextUpdate: " + toUtcString(halfHourBeforeNow));
    }

    private static String getNotAllowedBeforeAndAfter() {
        final var now = Instant.now();
        final var notAllowedBefore = new Date(now.toEpochMilli() - ALLOWED_TIME_SKEW_MILLIS);
        final var notAllowedAfter = new Date(now.toEpochMilli() + ALLOWED_TIME_SKEW_MILLIS);
        return "notAllowedBefore: " + toUtcString(notAllowedBefore) + ", "
            + "notAllowedAfter: " + toUtcString(notAllowedAfter) + ", ";
    }

}
