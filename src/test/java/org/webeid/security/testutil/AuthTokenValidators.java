/*
 * Copyright (c) 2020 The Web eID Project
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

package org.webeid.security.testutil;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.webeid.security.exceptions.JceException;
import org.webeid.security.validator.AuthTokenValidator;
import org.webeid.security.validator.AuthTokenValidatorBuilder;

import javax.cache.Cache;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;

public final class AuthTokenValidators {

    private static final String TOKEN_ORIGIN_URL = "https://ria.ee";
    private static final ASN1ObjectIdentifier EST_IDEMIA_POLICY = new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.1");

    public static AuthTokenValidator getAuthTokenValidator(Cache<String, LocalDateTime> cache) throws CertificateException, JceException {
        return getAuthTokenValidator(TOKEN_ORIGIN_URL, cache);
    }

    public static AuthTokenValidator getAuthTokenValidator(String url, Cache<String, LocalDateTime> cache) throws CertificateException, JceException {
        return getAuthTokenValidator(url, cache, getCACertificates());
    }

    public static AuthTokenValidator getAuthTokenValidator(String url, Cache<String, LocalDateTime> cache, X509Certificate... certificates) throws JceException {
        return getAuthTokenValidatorBuilder(url, cache, certificates)
            // Assure that all builder methods are covered with tests.
            .withAllowedClientClockSkew(Duration.ofMinutes(2))
            .withOcspRequestTimeout(Duration.ofSeconds(1))
            .withNonceDisabledOcspUrls(URI.create("http://example.org"))
            .withoutUserCertificateRevocationCheckWithOcsp()
            .build();
    }

    public static AuthTokenValidator getAuthTokenValidator(Cache<String, LocalDateTime> cache, String certFingerprint) throws CertificateException, JceException {
        return getAuthTokenValidatorBuilder(TOKEN_ORIGIN_URL, cache, getCACertificates())
            .withSiteCertificateSha256Fingerprint(certFingerprint)
            .withoutUserCertificateRevocationCheckWithOcsp()
            .build();
    }

    public static AuthTokenValidator getAuthTokenValidatorWithOcspCheck(Cache<String, LocalDateTime> cache) throws CertificateException, JceException {
        return getAuthTokenValidatorBuilder(TOKEN_ORIGIN_URL, cache, getCACertificates()).build();
    }

    public static AuthTokenValidator getAuthTokenValidatorWithWrongTrustedCA(Cache<String, LocalDateTime> cache) throws CertificateException, JceException {
        return getAuthTokenValidator(TOKEN_ORIGIN_URL, cache,
            CertificateLoader.loadCertificatesFromResources("ESTEID2018.cer"));
    }

    public static AuthTokenValidator getAuthTokenValidatorWithDisallowedESTEIDPolicy(Cache<String, LocalDateTime> cache) throws CertificateException, JceException {
        return getAuthTokenValidatorBuilder(TOKEN_ORIGIN_URL, cache, getCACertificates())
            .withDisallowedCertificatePolicies(EST_IDEMIA_POLICY)
            .build();
    }

    private static AuthTokenValidatorBuilder getAuthTokenValidatorBuilder(String uri, Cache<String, LocalDateTime> cache, X509Certificate[] certificates) {
        return new AuthTokenValidatorBuilder()
            .withSiteOrigin(URI.create(uri))
            .withNonceCache(cache)
            .withTrustedCertificateAuthorities(certificates);
    }

    private static X509Certificate[] getCACertificates() throws CertificateException {
        return CertificateLoader.loadCertificatesFromResources("TEST_of_ESTEID2018.cer");
    }

}
