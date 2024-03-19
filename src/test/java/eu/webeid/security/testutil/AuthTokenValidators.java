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

package eu.webeid.security.testutil;

import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.exceptions.OCSPCertificateException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;
import eu.webeid.security.validator.ocsp.OcspClient;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;

import static eu.webeid.security.testutil.OcspServiceMaker.getDesignatedOcspServiceConfiguration;

public final class AuthTokenValidators {

    private static final String TOKEN_ORIGIN_URL = "https://ria.ee";
    private static final ASN1ObjectIdentifier EST_IDEMIA_POLICY = new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.1");

    public static AuthTokenValidator getAuthTokenValidator() throws CertificateException, JceException, IOException {
        return getAuthTokenValidator(TOKEN_ORIGIN_URL);
    }

    public static AuthTokenValidator getAuthTokenValidator(String url) throws CertificateException, JceException, IOException {
        return getAuthTokenValidator(url, getCACertificates());
    }

    public static AuthTokenValidator getAuthTokenValidator(String url, X509Certificate... certificates) throws JceException {
        return getAuthTokenValidatorBuilder(url, certificates)
            // Assure that all builder methods are covered with tests.
            .withOcspRequestTimeout(Duration.ofSeconds(1))
            .withNonceDisabledOcspUrls(URI.create("http://example.org"))
            .withoutUserCertificateRevocationCheckWithOcsp()
            .build();
    }

    public static AuthTokenValidator getAuthTokenValidatorWithOverriddenOcspClient(OcspClient ocspClient) throws CertificateException, JceException, IOException {
        return getAuthTokenValidatorBuilder(TOKEN_ORIGIN_URL, getCACertificates())
            .withOcspClient(ocspClient)
            .build();
    }

    public static AuthTokenValidator getAuthTokenValidatorWithOcspCheck() throws CertificateException, JceException, IOException {
        return getAuthTokenValidatorBuilder(TOKEN_ORIGIN_URL, getCACertificates())
            .build();
    }

    public static AuthTokenValidator getAuthTokenValidatorWithDesignatedOcspCheck() throws CertificateException, JceException, IOException, OCSPCertificateException {
        return getAuthTokenValidatorBuilder(TOKEN_ORIGIN_URL, getCACertificates())
            .withDesignatedOcspServiceConfiguration(getDesignatedOcspServiceConfiguration())
            .build();
    }

    public static AuthTokenValidator getAuthTokenValidatorWithWrongTrustedCA() throws CertificateException, JceException, IOException {
        return getAuthTokenValidator(TOKEN_ORIGIN_URL,
            CertificateLoader.loadCertificatesFromResources("ESTEID2018.cer"));
    }

    public static AuthTokenValidator getAuthTokenValidatorWithDisallowedESTEIDPolicy() throws CertificateException, JceException, IOException {
        return getAuthTokenValidatorBuilder(TOKEN_ORIGIN_URL, getCACertificates())
            .withDisallowedCertificatePolicies(EST_IDEMIA_POLICY)
            .withoutUserCertificateRevocationCheckWithOcsp()
            .build();
    }

    private static AuthTokenValidatorBuilder getAuthTokenValidatorBuilder(String uri, X509Certificate[] certificates) {
        return new AuthTokenValidatorBuilder()
            .withSiteOrigin(URI.create(uri))
            .withTrustedCertificateAuthorities(certificates);
    }

    private static X509Certificate[] getCACertificates() throws CertificateException, IOException {
        return CertificateLoader.loadCertificatesFromResources("TEST_of_ESTEID2018.cer");
    }

}
