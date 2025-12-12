// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.testutil;

import org.junit.jupiter.api.BeforeEach;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.validator.AuthTokenValidator;

import java.io.IOException;
import java.security.cert.CertificateException;

import static eu.webeid.security.testutil.AuthTokenValidators.getAuthTokenValidator;

public abstract class AbstractTestWithValidator {

    /*
     * notBefore Time UTCTime 2025-06-05 09:48:06 UTC
     *  notAfter Time UTCTime 2030-05-26 20:59:59 UTC
     */
    public static final String VALID_AUTH_TOKEN = "{\"algorithm\":\"ES384\"," +
        "\"unverifiedCertificate\":\"MIIEDTCCA2+gAwIBAgIQa4KLRyy89ijWxYGOlhn62TAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTI1MDYwNTA5NDgwNloXDTMwMDUyNjIwNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAReCgD7V8bTpgy72fL9Fzx9zdN2Qlrn+UVZnwZttB5wJyhOBaXHow6aaoD+te/ep4PpGMTxJZp/FDm8PwHU7MO6aFuAT5w/0lLDfl1KHXvPR5cf/RLP1qi4RUfMwjJI5DajggHNMIIByTAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFMCEmSnETp87AjT2meEKVgAIKT57MHMGCCsGAQUFBwEBBGcwZTA1BggrBgEFBQcwAoYpaHR0cDovL2Muc2suZWUvVGVzdF9vZl9FU1RFSUQyMDE4LmRlci5jcnQwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MB8GA1UdEQQYMBaBFDM4MDAxMDg1NzE4QGVlc3RpLmVlMEcGA1UdIARAMD4wMgYLKwYBBAGDkSEBAQEwIzAhBggrBgEFBQcCARYVaHR0cHM6Ly93d3cuc2suZWUvQ1BTMAgGBgQAj3oBAjAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwawYIKwYBBQUHAQMEXzBdMAgGBgQAjkYBATBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAmVuMB0GA1UdDgQWBBRPJi71QGoBPJ3gaWAg9hPaMKjHpzAOBgNVHQ8BAf8EBAMCA4gwCgYIKoZIzj0EAwQDgYsAMIGHAkIBCgLGWbJ+zHMuno36ArmPanGIyry85orjDSkI3qSpp02SVlRui3Te25s2DZoEPspEFktVHkDP+ElkCJzs+fVOiX8CQQnRI1BxeKyExNPre+mvyYS5dXnDTuGAgjqVpELaY0IeROkcHnYq62CZnYElpN/xl8KLhYe9YkG1V7zDqF9zlpAU\"," +
        "\"appVersion\":\"https://web-eid.eu/web-eid-app/releases/2.5.0+0\"," +
        "\"signature\":\"pHkO+vRxBkP/zZLFvXcwR9kme/HT/DBRLk5RJDp7lPrfr6Qlb5Fu3/C3Up6Qw8P0KE2992as1lG9L3tbvqwa3dUCUz0osfRNEUXgkx1oPJrfII50/6L3mNnmexRnVSl2\"," +
        "\"format\":\"web-eid:1.0\"}";

    /* 
     * notBefore Time UTCTime 2021-07-22 12:43:08 UTC
     *  notAfter Time UTCTime 2026-07-09 21:59:59 UTC
     */
    public static final String LEGACY_AUTH_TOKEN_2021 = "{\"algorithm\":\"ES384\"," +
        "\"unverifiedCertificate\":\"MIIEBDCCA2WgAwIBAgIQY5OGshxoPMFg+Wfc0gFEaTAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTIxMDcyMjEyNDMwOFoXDTI2MDcwOTIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQmwEKsJTjaMHSaZj19hb9EJaJlwbKc5VFzmlGMFSJVk4dDy+eUxa5KOA7tWXqzcmhh5SYdv+MxcaQKlKWLMa36pfgv20FpEDb03GCtLqjLTRZ7649PugAQ5EmAqIic29CjggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFPlp/ceABC52itoqppEmbf71TJz6MGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgDCAgybz0u3W+tGI+AX+PiI5CrE9ptEHO5eezR1Jo4j7iGaO0i39xTGUB+NSC7P6AQbyE/ywqJjA1a62jTLcS9GHAJCARxN4NO4eVdWU3zVohCXm8WN3DWA7XUcn9TZiLGQ29P4xfQZOXJi/z4PNRRsR4plvSNB3dfyBvZn31HhC7my8woi\"," +
        "\"appVersion\":\"https://web-eid.eu/web-eid-app/releases/2.5.0+0\"," +
        "\"signature\":\"0Ov7ME6pTY1K2GXMj8Wxov/o2fGIMEds8OMY5dKdkB0nrqQX7fG1E5mnsbvyHpMDecMUH6Yg+p1HXdgB/lLqOcFZjt/OVXPjAAApC5d1YgRYATDcxsR1zqQwiNcHdmWn\"," +
        "\"format\":\"web-eid:1.0\"}";
    public static final String VALID_AUTH_TOKEN_TEST_DATE = "2026-01-01";
    public static final String VALID_CHALLENGE_NONCE = "12345678123456781234567812345678912356789123";

    protected AuthTokenValidator validator;
    protected WebEidAuthToken validAuthToken;

    @BeforeEach
    protected void setup() {
        try {
            validator = AuthTokenValidators.getAuthTokenValidator();
            validAuthToken = validator.parse(VALID_AUTH_TOKEN);
        } catch (CertificateException | IOException | AuthTokenException e) {
            throw new RuntimeException(e);
        }
    }

    protected WebEidAuthToken replaceTokenField(String token, String field, String value) throws AuthTokenException {
        final String tokenWithReplacedAlgorithm = token.replace(field, value);
        return validator.parse(tokenWithReplacedAlgorithm);
    }
}
