// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.config;

import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

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
            // Do not call the real OCSP service in tests.
            .withCertificateRevocationChecker((subjectCertificate, issuerCertificate) -> List.of())
            .build();
    }

}
