// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.config;

import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import javax.security.auth.x500.X500Principal;
import java.net.URI;
import java.util.List;

/**
 * Provides an {@link AuthTokenValidator} that does not call the real OCSP service.
 * <p>
 * Certificate trust validation is performed as usual, only the revocation check is replaced with a
 * no-op {@code CertificateRevocationChecker}.
 */
@TestConfiguration
public class TestValidatorConfiguration {

    @Bean
    @Primary
    AuthTokenValidator validatorWithoutOcspCall(ValidationConfiguration validationConfiguration,
                                               YAMLConfig yamlConfig) throws JceException {
        return new AuthTokenValidatorBuilder()
            .withSiteOrigin(URI.create(yamlConfig.getLocalOrigin()))
            .withTrustedCertificateAuthorities(validationConfiguration.loadTrustedCACertificatesFromCerFiles())
            .withTrustedCertificateAuthorities(validationConfiguration.loadTrustedCACertificatesFromTrustStore(yamlConfig))
            .withAllowedCertificatePolicies(
                new X500Principal(
                    "CN=TEST of ESTEID2018,2.5.4.97=#0c0e4e545245452d3130373437303133," +
                        "O=SK ID Solutions AS,C=EE"
                ),
                new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.1")
            )
            // Do not call the real OCSP service in tests.
            .withCertificateRevocationChecker((subjectCertificate, issuerCertificate) -> List.of())
            .build();
    }

}
