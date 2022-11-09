/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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
import eu.webeid.security.testutil.AbstractTestWithValidator;
import eu.webeid.security.testutil.AuthTokenValidators;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static eu.webeid.security.util.Strings.toTitleCase;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthTokenSignatureTest extends AbstractTestWithValidator {

    static final String AUTH_TOKEN_WRONG_CERT = "{\"algorithm\":\"ES384\"," +
        "\"unverifiedCertificate\":\"MIIEBDCCA2WgAwIBAgIQH9NeN14jo0ReaircrN2YvDAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTIwMDMxMjEyMjgxMloXDTI1MDMxMjIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARVeP+9l3b1mm3fMHPeCFLbD7esXI8lDc+soWCBoMnZGo3d2Rg/mzKCIWJtw+JhcN7RwFFH9cwZ8Gni4C3QFYBIIJ2GdjX2KQfEkDvRsnKw6ZZmJQ+HC4ZFew3r8gauhfejggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFOfk7lPOq6rb9IbFZF1q97kJ4s2iMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgEQRbzFOSHIcmIEKczhN8xuteYgN2zEXZSJdP0q1iH1RR2AzZ8Ddz6SKRn/bZSzjcd4b7h3AyOEQr2hcidYkxT7sAJCAMPtOUryqp2WbTEUoOpbWrKqp8GjaAiVpBGDn/Xdu5M2Z6dvwZHnFGgRrZXtyUbcAgRW7MQJ0s/9GCVro3iqUzNN\"," +
        "\"appVersion\":\"https://web-eid.eu/web-eid-app/releases/2.0.0+0\"," +
        "\"signature\":\"arx164xRiwhIQDINe0J+ZxJWZFOQTx0PBtOaWaxAe7gofEIHRIbV1w0sOCYBJnvmvMem9hU4nc2+iJx2x8poYck4Z6eI3GwtiksIec3XQ9ZIk1n/XchXnmPn3GYV+HzJ\"," +
        "\"format\":\"web-eid:1.0\"}";

    @Test
    void whenValidTokenAndNonce_thenValidationSucceeds() throws Exception {
        final X509Certificate result = validator.validate(validAuthToken, VALID_CHALLENGE_NONCE);

        assertThat(CertificateData.getSubjectCN(result))
            .isEqualTo("JÕEORG\\,JAAK-KRISTJAN\\,38001085718");
        assertThat(toTitleCase(CertificateData.getSubjectGivenName(result)))
            .isEqualTo("Jaak-Kristjan");
        assertThat(toTitleCase(CertificateData.getSubjectSurname(result)))
            .isEqualTo("Jõeorg");
        assertThat(CertificateData.getSubjectIdCode(result))
            .isEqualTo("PNOEE-38001085718");
        assertThat(CertificateData.getSubjectCountryCode(result))
            .isEqualTo("EE");
    }

    @Test
    void whenValidTokenAndWrongChallengeNonce_thenValidationFails() {
        final String invalidChallengeNonce = "12345678123456781234567812345678912356789124";
        assertThatThrownBy(() -> validator
            .validate(validAuthToken, invalidChallengeNonce))
            .isInstanceOf(AuthTokenSignatureValidationException.class);
    }

    @Test
    void whenValidTokenAndWrongOrigin_thenValidationFails() throws Exception {
        final AuthTokenValidator authTokenValidator = AuthTokenValidators.getAuthTokenValidator("https://invalid.org");
        assertThatThrownBy(() -> authTokenValidator
            .validate(validAuthToken, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenSignatureValidationException.class);
    }

    @Test
    void whenTokenWithWrongCert_thenValidationFails() throws Exception {
        final AuthTokenValidator authTokenValidator = AuthTokenValidators.getAuthTokenValidator();
        final WebEidAuthToken authTokenWithWrongCert = authTokenValidator.parse(AUTH_TOKEN_WRONG_CERT);
        assertThatThrownBy(() -> authTokenValidator
            .validate(authTokenWithWrongCert, VALID_CHALLENGE_NONCE))
            .isInstanceOf(AuthTokenSignatureValidationException.class);
    }

}
