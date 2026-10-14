// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.config;

import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import eu.webeid.security.challenge.ChallengeNonceGeneratorBuilder;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.AuthTokenValidator;
import eu.webeid.security.validator.AuthTokenValidatorBuilder;

import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

@Configuration
public class ValidationConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(ValidationConfiguration.class);

    private static final long CHALLENGE_NONCE_TTL_MINUTES = 5;
    private static final String CERTS_RESOURCE_PATH = "/certs/";
    public static final String TRUSTED_CERTIFICATES_JKS = "trusted_certificates.jks";

    /**
     * Test document policies for Estonian ID cards, digital ID cards, residence permit cards and diplomatic
     * identity cards issued under the ESTEID2018 and eID certificate-policy generations, grouped by issuer distinguished name.
     *
     * @see <a href="https://www.id.ee/en/article/certificate-policy-for-identity-card-digital-identity-card-residence-permit-card-and-diplomatic-identity-card-2/">
     *     ID.ee certificate policy index for Estonian identity documents</a>
     * @see <a href="https://www.id.ee/wp-content/uploads/2026/08/cp_esteid_v4.1_17.08.2026_allkirjastatud.pdf">
     *     IDEMIA-generation certificate policy</a>
     * @see <a href="https://www.id.ee/wp-content/uploads/2026/06/eid-cp-v-2.0_04.06.2026_allkirjastatud.pdf">
     *     Thales-generation certificate policy</a>
     * @see <a href="https://repository.eidpki.ee/static/documents/CertificateProfiles-20260520.pdf">
     *     ESTEID2025 certificate profile</a>
     */
    public static final Map<X500Principal, Set<ASN1ObjectIdentifier>> ESTEID_TEST_DOCUMENT_POLICIES = Map.of(
        new X500Principal(
            "CN=TEST of ESTEID2018,2.5.4.97=#0c0e4e545245452d3130373437303133,O=SK ID Solutions AS,C=EE"
        ), Set.of(
            // https://www.id.ee/wp-content/uploads/2026/08/cp_esteid_v4.1_17.08.2026_allkirjastatud.pdf Chapter 1.2. Document Name and Identification
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.1"), // Identity card of Estonian citizens
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.2"), // Identity card of European Union citizens
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.3"), // Digital identity card for Estonian residents
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.4"), // Digital identity card for e-residents
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.5"), // Residence permit card for long-term residents
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.6"), // Residence permit card for temporary residents and NATO SOFA
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.7"), // Residence permit card for family members of European Union citizens
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51455.1.2.1")  // Diplomatic identity card
        ),
        new X500Principal(
            "C=EE,O=Zetes Estonia OÜ,2.5.4.97=#0c0e4e545245452d3137303636303439,CN=Test ESTEID2025"
        ), Set.of(
            // https://www.id.ee/wp-content/uploads/2026/06/eid-cp-v-2.0_04.06.2026_allkirjastatud.pdf Chapter 1.2. Document Name and Identification
            // https://repository.eidpki.ee/static/documents/CertificateProfiles-20260520.pdf  According to the general practice, the propriotary OIDs for UAT and test certificates will be prefixed with “2.999.“ to differentiate them from the production OID’s.
            new ASN1ObjectIdentifier("2.999.1.3.6.1.4.1.51361.2.1.1"), // Identity card of Estonian citizens
            new ASN1ObjectIdentifier("2.999.1.3.6.1.4.1.51361.2.1.2"), // Identity card of European Union citizens
            new ASN1ObjectIdentifier("2.999.1.3.6.1.4.1.51361.2.1.3"), // Residence permit card for long-term residents
            new ASN1ObjectIdentifier("2.999.1.3.6.1.4.1.51361.2.1.4"), // Residence permit card for temporary residents and the right of stay in the Republic of Estonia.
            new ASN1ObjectIdentifier("2.999.1.3.6.1.4.1.51361.2.1.5"), // Residence permit card for family members of EU and UK citizens and the right of residence of UK citizens
            new ASN1ObjectIdentifier("2.999.1.3.6.1.4.1.51361.2.1.6"), // Digital identity card of e-residents
            new ASN1ObjectIdentifier("2.999.1.3.6.1.4.1.51455.2.1.1")  // Diplomatic identity card
        )
    );

    @Value("${spring.profiles.active}")
    private String activeProfile;

    @Bean
    public ChallengeNonceStore sessionBasedChallengeNonceStore(ObjectFactory<HttpSession> httpSessionFactory) {
        return new SessionBackedChallengeNonceStore(httpSessionFactory);
    }

    @Bean
    public ChallengeNonceGenerator generator(ChallengeNonceStore challengeNonceStore) {
        return new ChallengeNonceGeneratorBuilder()
                .withNonceTtl(Duration.ofMinutes(CHALLENGE_NONCE_TTL_MINUTES))
                .withChallengeNonceStore(challengeNonceStore)
                .build();
    }

    @Bean
    public AuthTokenValidator validator(YAMLConfig yamlConfig) {
        try {
            AuthTokenValidatorBuilder authTokenValidatorBuilder = new AuthTokenValidatorBuilder().withSiteOrigin(URI.create(yamlConfig.getLocalOrigin()))
                .withTrustedCertificateAuthorities(loadTrustedCACertificatesFromCerFiles())
                .withTrustedCertificateAuthorities(loadTrustedCACertificatesFromTrustStore(yamlConfig));

            if (!activeProfile.equals("prod")) {
                ESTEID_TEST_DOCUMENT_POLICIES
                    .forEach((x500Principal, asn1ObjectIdentifiers) ->
                        authTokenValidatorBuilder.withAllowedCertificatePolicies(x500Principal, asn1ObjectIdentifiers.toArray(new ASN1ObjectIdentifier[0])));

            }

            return authTokenValidatorBuilder.build();
        } catch (JceException e) {
            throw new RuntimeException("Error building the Web eID auth token validator.", e);
        }
    }

    X509Certificate[] loadTrustedCACertificatesFromCerFiles() {
        List<X509Certificate> caCertificates = new ArrayList<>();

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
            Resource[] resources = resolver.getResources(CERTS_RESOURCE_PATH + activeProfile + "/*.cer");

            for (Resource resource : resources) {
                try (InputStream stream = resource.getInputStream()) {
                    caCertificates.add((X509Certificate) certFactory.generateCertificate(stream));
                }
            }

        } catch (CertificateException | IOException e) {
            throw new RuntimeException("Error initializing trusted CA certificates.", e);
        }

        return caCertificates.toArray(X509Certificate[]::new);
    }

    X509Certificate[] loadTrustedCACertificatesFromTrustStore(YAMLConfig yamlConfig) {
        List<X509Certificate> caCertificates = new ArrayList<>();

        try (InputStream is = ValidationConfiguration.class.getResourceAsStream(CERTS_RESOURCE_PATH + activeProfile + "/" + TRUSTED_CERTIFICATES_JKS)) {
            if (is == null) {
                LOG.info("Truststore file {} not found for {} profile", TRUSTED_CERTIFICATES_JKS, activeProfile);
                return new X509Certificate[0];
            }
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, yamlConfig.getTrustStorePassword().toCharArray());
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
                caCertificates.add(certificate);
            }
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error initializing trusted CA certificates from trust store.", e);
        }

        return caCertificates.toArray(X509Certificate[]::new);
    }



}
