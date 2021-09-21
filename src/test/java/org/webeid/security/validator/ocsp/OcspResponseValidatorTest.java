package org.webeid.security.validator.ocsp;

import okhttp3.ResponseBody;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.Test;
import org.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import org.webeid.security.testutil.Dates;
import org.webeid.security.validator.validators.SubjectCertificateNotRevokedValidator;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.webeid.security.validator.ocsp.OcspResponseValidator.validateCertificateStatusUpdateTime;

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
