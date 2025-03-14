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

package eu.webeid.security.testutil;

import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.exceptions.CertificateDecodingException;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Certificates {

    private static final String JAAK_KRISTJAN_ESTEID2018_CERT = "MIIEAzCCA2WgAwIBAgIQOWkBWXNDJm1byFd3XsWkvjAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE4MTAxODA5NTA0N1oXDTIzMTAxNzIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR5k1lXzvSeI9O/1s1pZvjhEW8nItJoG0EBFxmLEY6S7ki1vF2Q3TEDx6dNztI1Xtx96cs8r4zYTwdiQoDg7k3diUuR9nTWGxQEMO1FDo4Y9fAmiPGWT++GuOVoZQY3XxijggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFOQsvTQJEBVMMSmhyZX5bibYJubAMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBiwAwgYcCQgH1UsmMdtLZti51Fq2QR4wUkAwpsnhsBV2HQqUXFYBJ7EXnLCkaXjdZKkHpABfM0QEx7UUhaI4i53jiJ7E1Y7WOAAJBDX4z61pniHJapI1bkMIiJQ/ti7ha8fdJSMSpAds5CyHIyHkQzWlVy86f9mA7Eu3oRO/1q+eFUzDbNN3Vvy7gQWQ=";
    private static final String MARILIIS_ESTEID2015_CERT = "MIIFwjCCA6qgAwIBAgIQY+LgQ6n0BURZ048wIEiYHjANBgkqhkiG9w0BAQsFADBrMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHzAdBgNVBAMMFlRFU1Qgb2YgRVNURUlELVNLIDIwMTUwHhcNMTcxMDAzMTMyMjU2WhcNMjIxMDAyMjA1OTU5WjCBnjELMAkGA1UEBhMCRUUxDzANBgNVBAoMBkVTVEVJRDEaMBgGA1UECwwRZGlnaXRhbCBzaWduYXR1cmUxJjAkBgNVBAMMHU3DhE5OSUssTUFSSS1MSUlTLDYxNzEwMDMwMTYzMRAwDgYDVQQEDAdNw4ROTklLMRIwEAYDVQQqDAlNQVJJLUxJSVMxFDASBgNVBAUTCzYxNzEwMDMwMTYzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+nNdtmZ2Ve3XXtjBEGwpvVrDIg7slPfLlyHbCBFMXevfqW5KsXIOy6E2A+Yof+/cqRlY4IhsX2Ka9SsJSo8/EekasFasLFPw9ZBE3MG0nn5zaatg45VSjnPinMmrzFzxo4IB2jCCAdYwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBkAwgYsGA1UdIASBgzCBgDBzBgkrBgEEAc4fAwEwZjAvBggrBgEFBQcCARYjaHR0cHM6Ly93d3cuc2suZWUvcmVwb3NpdG9vcml1bS9DUFMwMwYIKwYBBQUHAgIwJwwlQWludWx0IHRlc3RpbWlzZWtzLiBPbmx5IGZvciB0ZXN0aW5nLjAJBgcEAIvsQAECMB0GA1UdDgQWBBTiw6M0uow+u6sfhgJAWCSvtkB/ejAiBggrBgEFBQcBAwQWMBQwCAYGBACORgEBMAgGBgQAjkYBBDAfBgNVHSMEGDAWgBRJwPJEOWXVm0Y7DThgg7HWLSiGpjCBgwYIKwYBBQUHAQEEdzB1MCwGCCsGAQUFBzABhiBodHRwOi8vYWlhLmRlbW8uc2suZWUvZXN0ZWlkMjAxNTBFBggrBgEFBQcwAoY5aHR0cHM6Ly9zay5lZS91cGxvYWQvZmlsZXMvVEVTVF9vZl9FU1RFSUQtU0tfMjAxNS5kZXIuY3J0MEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly93d3cuc2suZWUvY3Jscy9lc3RlaWQvdGVzdF9lc3RlaWQyMDE1LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAEWBdwmzo/yRncJXKvrE+A1G6yQaBNarKectI5uk18BewYEA4QkhmIwOCwD83jBDB9JF+kuODMHsnvz2mfhwaB/uJIPwfBDQ5JCMBdHPsxLN9nzW/UUzqv2UDMwFkibHCcfV5lTBcmOd7FagUHTUm+8gRlWbDiVl5yPochdJgGYPV+fs/jc5ttHaBvBon0z9LbI4qi0VXdRmV0iogErh8JF5yfGkbfGRaMkWkNYQtQ68i/hPe6MaUxL2/MMt4YTyXtVghmc3ZKZIyp4j0+jlK4vL+d4gaE+TvoQvh6HrmP145FqlMDurATWdB069+hdDLO5fI6AYkc79D5XPKwQ/f1MBufLtBYtOJmtpLT+tdBt/EqOEIO/0FeHcXZlFioNMuxBBeTE/QcDtJ2jxTcg8jNOoepS0wjuxBon9iI1710SR53DLGSWdL52lPoBFacnyPQI1htXVUkJ8icMQKYe3BLt1Ha2cvsA4n4IpjqVROX4mzoPL1hg/aJlD+W2uI2ppYRUNY5FX7C0R+AYzMpOahQ7STQfUxtEnKW98e1I33LWwpjJW9q4htsZeXs4Zatf9ssfUW0VA49tnI28kkN2D8aw1NgWfzVlnJKkEj0qa3ewLZK577j8MexAetT/7leH6mqewr9ewC/tKbYjhufieXx6RPcRC4OZsxtii7ih8TqRg=";
    private static final String ORGANIZATION_CERT = "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";

    private static X509Certificate testEsteid2018CA;
    private static X509Certificate testEsteid2015CA;

    private static X509Certificate jaakKristjanEsteid2018Cert;
    private static X509Certificate mariliisEsteid2015Cert;
    private static X509Certificate organizationCert;
    private static X509Certificate testSkOcspResponder2020;

    static void loadCertificates() throws CertificateException, IOException {
        X509Certificate[] certificates = CertificateLoader.loadCertificatesFromResources("TEST_of_ESTEID-SK_2015.cer", "TEST_of_ESTEID2018.cer", "TEST_of_SK_OCSP_RESPONDER_2020.cer");
        testEsteid2015CA = certificates[0];
        testEsteid2018CA = certificates[1];
        testSkOcspResponder2020 = certificates[2];
    }

    public static X509Certificate getTestEsteid2018CA() throws CertificateException, IOException {
        if (testEsteid2018CA == null) {
            loadCertificates();
        }
        return testEsteid2018CA;
    }

    public static X509Certificate getTestEsteid2015CA() throws CertificateException, IOException {
        if (testEsteid2015CA == null) {
            loadCertificates();
        }
        return testEsteid2015CA;
    }

    public static X509Certificate getTestSkOcspResponder2020() throws CertificateException, IOException {
        if (testSkOcspResponder2020 == null) {
            loadCertificates();
        }
        return testSkOcspResponder2020;
    }

    public static X509Certificate getJaakKristjanEsteid2018Cert() throws CertificateDecodingException {
        if (jaakKristjanEsteid2018Cert == null) {
            jaakKristjanEsteid2018Cert = CertificateLoader.decodeCertificateFromBase64(JAAK_KRISTJAN_ESTEID2018_CERT);
        }
        return jaakKristjanEsteid2018Cert;
    }

    public static X509Certificate getMariliisEsteid2015Cert() throws CertificateDecodingException {
        if (mariliisEsteid2015Cert == null) {
            mariliisEsteid2015Cert = CertificateLoader.decodeCertificateFromBase64(MARILIIS_ESTEID2015_CERT);
        }
        return mariliisEsteid2015Cert;
    }

    public static X509Certificate getOrganizationCert() throws CertificateDecodingException {
        if (organizationCert == null) {
            organizationCert = CertificateLoader.decodeCertificateFromBase64(ORGANIZATION_CERT);
        }
        return organizationCert;
    }

}
