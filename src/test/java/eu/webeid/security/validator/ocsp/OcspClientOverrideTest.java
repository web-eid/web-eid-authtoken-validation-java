// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.ocsp;

import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.testutil.AbstractTestWithValidator;
import eu.webeid.security.testutil.AuthTokenValidators;
import eu.webeid.security.util.DateAndTime;
import eu.webeid.security.validator.AuthTokenValidator;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.cert.CertificateException;
import java.time.Duration;

import static eu.webeid.security.testutil.DateMocker.mockDate;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mockStatic;

class OcspClientOverrideTest extends AbstractTestWithValidator {
    private MockedStatic<DateAndTime.DefaultClock> mockedClock;

    @Override
    @BeforeEach
    protected void setup() {
        super.setup();
        mockedClock = mockStatic(DateAndTime.DefaultClock.class);
        // Ensure that the certificates do not expire.
        mockDate("2021-07-23", mockedClock);
    }

    @AfterEach
    void tearDown() {
        mockedClock.close();
    }

    @Test
    void whenOcspClientIsOverridden_thenItIsUsed() throws JceException, CertificateException, IOException {
        final AuthTokenValidator validator = AuthTokenValidators.getAuthTokenValidatorWithOverriddenOcspClient(new OcpClientThatThrows());
        assertThatThrownBy(() -> validator.validate(validAuthToken, VALID_CHALLENGE_NONCE))
            .cause()
            .isInstanceOf(OcpClientThatThrowsException.class);
    }

    @Test
    @Disabled("Demonstrates how to configure the built-in HttpClient instance for OcspClientImpl")
    void whenOcspClientIsConfiguredWithCustomHttpClient_thenOcspCallSucceeds() throws JceException, CertificateException, IOException {
        final AuthTokenValidator validator = AuthTokenValidators.getAuthTokenValidatorWithOverriddenOcspClient(
            new OcspClientImpl(HttpClient.newBuilder().build(), Duration.ofSeconds(5))
        );
        assertThatCode(() -> validator.validate(validAuthToken, VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
    }

    private static class OcpClientThatThrows implements OcspClient {
        @Override
        public OCSPResp request(URI url, OCSPReq request) throws IOException {
            throw new OcpClientThatThrowsException();
        }
    }

    private static class OcpClientThatThrowsException extends IOException {
    }

}
