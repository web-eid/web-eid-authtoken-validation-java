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

package eu.webeid.ocsp.client;

import eu.webeid.ocsp.OcspCertificateRevocationChecker;
import eu.webeid.ocsp.exceptions.OCSPClientException;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.testutil.AbstractTestWithValidator;
import eu.webeid.security.testutil.AuthTokenValidators;
import eu.webeid.security.validator.AuthTokenValidator;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.cert.CertificateException;
import java.time.Duration;

import static eu.webeid.ocsp.service.OcspServiceMaker.getAiaOcspServiceProvider;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// TODO Fix failing tests
@Disabled
class OcspClientOverrideTest extends AbstractTestWithValidator {

    @Test
    void whenOcspClientIsOverridden_thenItIsUsed() throws JceException, CertificateException, IOException {
        final AuthTokenValidator validator = getAuthTokenValidatorWithOverriddenOcspClient(new OcpClientThatThrows());
        assertThatThrownBy(() -> validator.validate(validAuthToken, VALID_CHALLENGE_NONCE))
            .cause()
            .isInstanceOf(OcpClientThatThrowsException.class);
    }

    @Test
    void whenInvalidOcspRequestTimeout_thenThrows() {
        assertThatThrownBy(() -> OcspClientImpl.build(Duration.ofMinutes(-1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("ocspRequestTimeout must be greater than zero");
    }

    /**
     * Demonstrates how to configure the built-in HttpClient instance for OcspClientImpl.
     */
    @Test
    void whenOcspClientIsConfiguredWithCustomHttpClient_thenOcspCallSucceeds() throws JceException, CertificateException, IOException {
        final AuthTokenValidator validator = getAuthTokenValidatorWithOverriddenOcspClient(
            new OcspClientImpl(HttpClient.newBuilder().build(), Duration.ofSeconds(5))
        );
        assertThatCode(() -> validator.validate(validAuthToken, VALID_CHALLENGE_NONCE))
            .doesNotThrowAnyException();
    }

    private static AuthTokenValidator getAuthTokenValidatorWithOverriddenOcspClient(OcspClient ocspClient) throws CertificateException, JceException, IOException {
        return AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
                .withCertificateRevocationChecker(new OcspCertificateRevocationChecker(
                        ocspClient,
                        getAiaOcspServiceProvider(),
                        OcspCertificateRevocationChecker.DEFAULT_TIME_SKEW,
                        OcspCertificateRevocationChecker.DEFAULT_THIS_UPDATE_AGE
                )).build();
    }

    private static class OcpClientThatThrows implements OcspClient {
        @Override
        public OCSPResp request(URI url, OCSPReq request) throws OCSPClientException {
            throw new OcpClientThatThrowsException();
        }
    }

    private static class OcpClientThatThrowsException extends OCSPClientException {
    }

}
