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

package eu.webeid.security.validator;

import eu.webeid.security.certificate.SubjectCertificatePolicies;
import eu.webeid.security.testutil.Certificates;
import eu.webeid.security.validator.revocationcheck.CertificateRevocationChecker;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.net.URI;
import java.security.cert.PKIXRevocationChecker;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.Mockito.mock;

class AuthTokenValidationConfigurationTest {

    private static final ASN1ObjectIdentifier ALLOWED_POLICY = new ASN1ObjectIdentifier("1.2.3");
    private static final X500Principal ISSUER = new X500Principal("CN=Example CA");

    @Test
    void allowedPoliciesAreEmptyByDefault() {
        final AuthTokenValidationConfiguration configuration = new AuthTokenValidationConfiguration();

        assertThat(configuration.getAllowedSubjectCertificatePolicies())
            .isEmpty();
    }

    @Test
    void copyRetainsAllowedPoliciesIndependently() {
        final AuthTokenValidationConfiguration configuration = new AuthTokenValidationConfiguration();
        configuration.setAllowedSubjectCertificatePolicies(ISSUER, List.of(ALLOWED_POLICY));

        final AuthTokenValidationConfiguration copy = configuration.copy();
        configuration.getAllowedSubjectCertificatePolicies().clear();

        assertThat(copy.getAllowedSubjectCertificatePolicies())
            .containsEntry(ISSUER, Set.of(ALLOWED_POLICY));
    }

    @Test
    void setAllowedPoliciesCopiesInputCollection() {
        final List<ASN1ObjectIdentifier> policies = new ArrayList<>(List.of(ALLOWED_POLICY));
        final AuthTokenValidationConfiguration configuration = new AuthTokenValidationConfiguration();

        configuration.setAllowedSubjectCertificatePolicies(ISSUER, policies);
        policies.clear();

        assertThat(configuration.getAllowedSubjectCertificatePolicies())
            .containsOnly(entry(ISSUER, Set.of(ALLOWED_POLICY)));
    }

    @Test
    void subsequentAllowedPolicyConfigurationAddsAnotherIssuer() {
        final X500Principal anotherIssuer = new X500Principal("CN=Another CA");
        final ASN1ObjectIdentifier anotherPolicy = new ASN1ObjectIdentifier("1.2.4");
        final AuthTokenValidationConfiguration configuration = new AuthTokenValidationConfiguration();

        configuration.setAllowedSubjectCertificatePolicies(ISSUER, List.of(ALLOWED_POLICY));
        configuration.setAllowedSubjectCertificatePolicies(anotherIssuer, List.of(anotherPolicy));

        assertThat(configuration.getAllowedSubjectCertificatePolicies())
            .containsOnly(
                entry(ISSUER, Set.of(ALLOWED_POLICY)),
                entry(anotherIssuer, Set.of(anotherPolicy))
            );
    }

    @Test
    void settingNoAllowedPoliciesRemovesIssuerEntry() {
        final X500Principal defaultIssuer = SubjectCertificatePolicies.ESTEID_PRODUCTION_DOCUMENT_POLICIES
            .keySet().iterator().next();
        final AuthTokenValidationConfiguration configuration = new AuthTokenValidationConfiguration();

        configuration.setAllowedSubjectCertificatePolicies(defaultIssuer, List.of());

        assertThat(configuration.getAllowedSubjectCertificatePolicies())
            .doesNotContainKey(defaultIssuer);
    }

    @Test
    void whenNoCustomCheckerProvided_thenRevocationModeIsPlatformOcsp() throws Exception {
        final AuthTokenValidationConfiguration configuration = getValidConfiguration();
        configuration.validate();
        assertThat(configuration.getRevocationMode()).isEqualTo(RevocationMode.PLATFORM_OCSP);
    }

    @Test
    void whenRevocationCheckDisabled_thenRevocationModeIsDisabled() throws Exception {
        final AuthTokenValidationConfiguration configuration = getValidConfiguration();
        configuration.setUserCertificateRevocationCheckDisabled();
        configuration.validate();
        assertThat(configuration.getRevocationMode()).isEqualTo(RevocationMode.DISABLED);
    }

    @Test
    void whenCustomCheckerConfigured_thenRevocationModeIsCustomChecker() throws Exception {
        final AuthTokenValidationConfiguration configuration = getValidConfiguration();
        configuration.setCertificateRevocationChecker(getNoopChecker());
        configuration.validate();
        assertThat(configuration.getRevocationMode()).isEqualTo(RevocationMode.CUSTOM_CHECKER);
    }

    @Test
    void whenCustomPkixCheckerConfigured_thenRevocationModeIsCustomPkix() throws Exception {
        final AuthTokenValidationConfiguration configuration = getValidConfiguration();
        configuration.setPkixRevocationChecker(mock(PKIXRevocationChecker.class));
        configuration.validate();
        assertThat(configuration.getRevocationMode()).isEqualTo(RevocationMode.CUSTOM_PKIX);
    }

    private static AuthTokenValidationConfiguration getValidConfiguration() throws Exception {
        final AuthTokenValidationConfiguration configuration = new AuthTokenValidationConfiguration();
        configuration.setSiteOrigin(URI.create("https://ria.ee"));
        configuration.getTrustedCACertificates().add(Certificates.getTestEsteid2018CA());
        return configuration;
    }

    private static CertificateRevocationChecker getNoopChecker() {
        return (subjectCertificate, issuerCertificate) -> List.of();
    }
}
