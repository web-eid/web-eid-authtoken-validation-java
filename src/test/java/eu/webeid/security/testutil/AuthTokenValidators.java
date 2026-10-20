// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.testutil;

import eu.webeid.security.certificate.CertificateLoader;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public final class AuthTokenValidators {

    private static final String TOKEN_ORIGIN_URL = "https://ria.ee";
    private static final X500Principal EST_IDEMIA_TEST_ISSUER = new X500Principal(
        "CN=TEST of ESTEID2018,2.5.4.97=#0c0e4e545245452d3130373437303133,O=SK ID Solutions AS,C=EE"
    );
    private static final ASN1ObjectIdentifier EST_IDEMIA_PRODUCTION_POLICY =
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.1");
    private static final ASN1ObjectIdentifier EST_IDEMIA_TEST_POLICY =
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.1");

    public static AuthTokenValidator getAuthTokenValidator() throws CertificateException, JceException, IOException {
        return getAuthTokenValidator(TOKEN_ORIGIN_URL);
    }

    public static AuthTokenValidator getAuthTokenValidator(String url) throws CertificateException, JceException, IOException {
        return getAuthTokenValidator(url, getCACertificates());
    }

    public static AuthTokenValidator getAuthTokenValidator(String url, X509Certificate... certificates) throws JceException {
        return getAuthTokenValidatorBuilder(url, certificates)
            .withoutUserCertificateRevocationCheck()
            .build();
    }

    public static AuthTokenValidator getAuthTokenValidatorWithOcspCheck() throws CertificateException, JceException, IOException {
        return getAuthTokenValidatorBuilder(TOKEN_ORIGIN_URL, getCACertificates())
            .build();
    }

    public static AuthTokenValidator getAuthTokenValidatorWithWrongTrustedCA() throws CertificateException, JceException, IOException {
        return getAuthTokenValidator(TOKEN_ORIGIN_URL,
            CertificateLoader.loadCertificatesFromResources("ESTEID2018.cer"));
    }

    public static AuthTokenValidator getAuthTokenValidatorWithJuly2024ExpiredUnrelatedTrustedCA() throws CertificateException, JceException, IOException {
        return getAuthTokenValidator(TOKEN_ORIGIN_URL,
            CertificateLoader.loadCertificatesFromResources("TEST_of_ESTEID2018.cer", "TEST_of_SK_OCSP_RESPONDER_2020.cer"));
    }

    public static AuthTokenValidator getAuthTokenValidatorWithDisallowedESTEIDPolicy() throws CertificateException, JceException, IOException {
        return new AuthTokenValidatorBuilder()
            .withSiteOrigin(URI.create(TOKEN_ORIGIN_URL))
            .withTrustedCertificateAuthorities(getCACertificates())
            .withDisallowedCertificatePolicies(EST_IDEMIA_TEST_POLICY)
            .withoutUserCertificateRevocationCheck()
            .build();
    }

    public static AuthTokenValidator getAuthTokenValidatorForBelgianIdCard() throws CertificateException, IOException, JceException {
      return getAuthTokenValidator(
                "https://47f0-46-131-86-189.ngrok-free.app",
                CertificateLoader.loadCertificatesFromResources("eID TEST EC Citizen CA.cer")
            );
    }

    public static AuthTokenValidator getAuthTokenValidatorForFinnishIdCard() throws CertificateException, IOException, JceException {
      return getAuthTokenValidator(
                "https://47f0-46-131-86-189.ngrok-free.app",
                CertificateLoader.loadCertificatesFromResources("DVV TEST Certificates - G5E.crt", "VRK TEST CA for Test Purposes - G4.crt")
            );
    }

    public static AuthTokenValidatorBuilder getDefaultAuthTokenValidatorBuilder() throws CertificateException, IOException {
        return getAuthTokenValidatorBuilder(TOKEN_ORIGIN_URL, getCACertificates());
    }

    private static AuthTokenValidatorBuilder getAuthTokenValidatorBuilder(String uri, X509Certificate[] certificates) {
        return new AuthTokenValidatorBuilder()
            .withSiteOrigin(URI.create(uri))
            .withTrustedCertificateAuthorities(certificates)
            .withAllowedCertificatePolicies(
                EST_IDEMIA_TEST_ISSUER,
                EST_IDEMIA_PRODUCTION_POLICY,
                EST_IDEMIA_TEST_POLICY
            );
    }

    private static X509Certificate[] getCACertificates() throws CertificateException, IOException {
        return CertificateLoader.loadCertificatesFromResources("TEST_of_ESTEID2018.cer");
    }

}
