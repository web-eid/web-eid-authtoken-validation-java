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

package eu.webeid.security.testutil;

import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.exceptions.CertificateDecodingException;
import eu.webeid.security.util.Sha256Digest;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Certificates {

    private static final String JAAK_KRISTJAN_ESTEID2018_CERT = "MIIEAzCCA2WgAwIBAgIQOWkBWXNDJm1byFd3XsWkvjAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE4MTAxODA5NTA0N1oXDTIzMTAxNzIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR5k1lXzvSeI9O/1s1pZvjhEW8nItJoG0EBFxmLEY6S7ki1vF2Q3TEDx6dNztI1Xtx96cs8r4zYTwdiQoDg7k3diUuR9nTWGxQEMO1FDo4Y9fAmiPGWT++GuOVoZQY3XxijggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFOQsvTQJEBVMMSmhyZX5bibYJubAMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBiwAwgYcCQgH1UsmMdtLZti51Fq2QR4wUkAwpsnhsBV2HQqUXFYBJ7EXnLCkaXjdZKkHpABfM0QEx7UUhaI4i53jiJ7E1Y7WOAAJBDX4z61pniHJapI1bkMIiJQ/ti7ha8fdJSMSpAds5CyHIyHkQzWlVy86f9mA7Eu3oRO/1q+eFUzDbNN3Vvy7gQWQ=";
    private static final String MARILIIS_ESTEID2015_CERT = "MIIFwjCCA6qgAwIBAgIQY+LgQ6n0BURZ048wIEiYHjANBgkqhkiG9w0BAQsFADBrMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHzAdBgNVBAMMFlRFU1Qgb2YgRVNURUlELVNLIDIwMTUwHhcNMTcxMDAzMTMyMjU2WhcNMjIxMDAyMjA1OTU5WjCBnjELMAkGA1UEBhMCRUUxDzANBgNVBAoMBkVTVEVJRDEaMBgGA1UECwwRZGlnaXRhbCBzaWduYXR1cmUxJjAkBgNVBAMMHU3DhE5OSUssTUFSSS1MSUlTLDYxNzEwMDMwMTYzMRAwDgYDVQQEDAdNw4ROTklLMRIwEAYDVQQqDAlNQVJJLUxJSVMxFDASBgNVBAUTCzYxNzEwMDMwMTYzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+nNdtmZ2Ve3XXtjBEGwpvVrDIg7slPfLlyHbCBFMXevfqW5KsXIOy6E2A+Yof+/cqRlY4IhsX2Ka9SsJSo8/EekasFasLFPw9ZBE3MG0nn5zaatg45VSjnPinMmrzFzxo4IB2jCCAdYwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBkAwgYsGA1UdIASBgzCBgDBzBgkrBgEEAc4fAwEwZjAvBggrBgEFBQcCARYjaHR0cHM6Ly93d3cuc2suZWUvcmVwb3NpdG9vcml1bS9DUFMwMwYIKwYBBQUHAgIwJwwlQWludWx0IHRlc3RpbWlzZWtzLiBPbmx5IGZvciB0ZXN0aW5nLjAJBgcEAIvsQAECMB0GA1UdDgQWBBTiw6M0uow+u6sfhgJAWCSvtkB/ejAiBggrBgEFBQcBAwQWMBQwCAYGBACORgEBMAgGBgQAjkYBBDAfBgNVHSMEGDAWgBRJwPJEOWXVm0Y7DThgg7HWLSiGpjCBgwYIKwYBBQUHAQEEdzB1MCwGCCsGAQUFBzABhiBodHRwOi8vYWlhLmRlbW8uc2suZWUvZXN0ZWlkMjAxNTBFBggrBgEFBQcwAoY5aHR0cHM6Ly9zay5lZS91cGxvYWQvZmlsZXMvVEVTVF9vZl9FU1RFSUQtU0tfMjAxNS5kZXIuY3J0MEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly93d3cuc2suZWUvY3Jscy9lc3RlaWQvdGVzdF9lc3RlaWQyMDE1LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAEWBdwmzo/yRncJXKvrE+A1G6yQaBNarKectI5uk18BewYEA4QkhmIwOCwD83jBDB9JF+kuODMHsnvz2mfhwaB/uJIPwfBDQ5JCMBdHPsxLN9nzW/UUzqv2UDMwFkibHCcfV5lTBcmOd7FagUHTUm+8gRlWbDiVl5yPochdJgGYPV+fs/jc5ttHaBvBon0z9LbI4qi0VXdRmV0iogErh8JF5yfGkbfGRaMkWkNYQtQ68i/hPe6MaUxL2/MMt4YTyXtVghmc3ZKZIyp4j0+jlK4vL+d4gaE+TvoQvh6HrmP145FqlMDurATWdB069+hdDLO5fI6AYkc79D5XPKwQ/f1MBufLtBYtOJmtpLT+tdBt/EqOEIO/0FeHcXZlFioNMuxBBeTE/QcDtJ2jxTcg8jNOoepS0wjuxBon9iI1710SR53DLGSWdL52lPoBFacnyPQI1htXVUkJ8icMQKYe3BLt1Ha2cvsA4n4IpjqVROX4mzoPL1hg/aJlD+W2uI2ppYRUNY5FX7C0R+AYzMpOahQ7STQfUxtEnKW98e1I33LWwpjJW9q4htsZeXs4Zatf9ssfUW0VA49tnI28kkN2D8aw1NgWfzVlnJKkEj0qa3ewLZK577j8MexAetT/7leH6mqewr9ewC/tKbYjhufieXx6RPcRC4OZsxtii7ih8TqRg=";

    private static final String RIA_EE_CERT = "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";

    private static X509Certificate testEsteid2018CA;
    private static X509Certificate testEsteid2015CA;

    private static X509Certificate jaakKristjanEsteid2018Cert;
    private static X509Certificate mariliisEsteid2015Cert;
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

    public static byte[] getRiaSiteCertificateSha256Hash() throws CertificateDecodingException, CertificateEncodingException {
        final X509Certificate certificate = CertificateLoader.decodeCertificateFromBase64(RIA_EE_CERT);
        return Sha256Digest.sha256Digest(certificate.getEncoded());
    }
}
