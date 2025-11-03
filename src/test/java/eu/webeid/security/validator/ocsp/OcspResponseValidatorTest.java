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

import eu.webeid.security.testutil.Dates;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.Test;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static eu.webeid.security.validator.ocsp.OcspResponseValidator.validateCertificateStatusUpdateTime;

class OcspResponseValidatorTest {

    @Test
    void whenThisUpdateDayBeforeProducedAt_thenThrows() throws Exception {
        final SingleResp mockResponse = mock(SingleResp.class);
        // yyyy-MM-dd'T'HH:mm:ss.SSSZ
        when(mockResponse.getThisUpdate()).thenReturn(Dates.create("2021-09-01T00:00:00.000Z"));
        final Date producedAt = Dates.create("2021-09-02T00:00:00.000Z");
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, producedAt))
            .withMessage("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "notAllowedBefore: 2021-09-01 23:45:00 UTC, "
                + "notAllowedAfter: 2021-09-02 00:15:00 UTC, "
                + "thisUpdate: 2021-09-01 00:00:00 UTC, "
                + "nextUpdate: null");
    }

    @Test
    void whenThisUpdateDayAfterProducedAt_thenThrows() throws Exception {
        final SingleResp mockResponse = mock(SingleResp.class);
        when(mockResponse.getThisUpdate()).thenReturn(Dates.create("2021-09-02"));
        final Date producedAt = Dates.create("2021-09-01");
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, producedAt))
            .withMessage("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "notAllowedBefore: 2021-08-31 23:45:00 UTC, "
                + "notAllowedAfter: 2021-09-01 00:15:00 UTC, "
                + "thisUpdate: 2021-09-02 00:00:00 UTC, "
                + "nextUpdate: null");
    }

    @Test
    void whenNextUpdateDayBeforeProducedAt_thenThrows() throws Exception {
        final SingleResp mockResponse = mock(SingleResp.class);
        when(mockResponse.getThisUpdate()).thenReturn(Dates.create("2021-09-02"));
        when(mockResponse.getNextUpdate()).thenReturn(Dates.create("2021-09-01"));
        final Date producedAt = Dates.create("2021-09-02");
        assertThatExceptionOfType(UserCertificateOCSPCheckFailedException.class)
            .isThrownBy(() ->
                validateCertificateStatusUpdateTime(mockResponse, producedAt))
            .withMessage("User certificate revocation check has failed: "
                + "Certificate status update time check failed: "
                + "notAllowedBefore: 2021-09-01 23:45:00 UTC, "
                + "notAllowedAfter: 2021-09-02 00:15:00 UTC, "
                + "thisUpdate: 2021-09-02 00:00:00 UTC, "
                + "nextUpdate: 2021-09-01 00:00:00 UTC");
    }

}
