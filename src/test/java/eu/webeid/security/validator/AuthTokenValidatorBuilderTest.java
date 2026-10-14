// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator;

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.certificate.SubjectCertificatePolicies;
import eu.webeid.security.testutil.AuthTokenValidators;
import eu.webeid.security.validator.revocationcheck.CertificateRevocationChecker;
import eu.webeid.security.validator.revocationcheck.RevocationMode;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

import javax.security.auth.x500.X500Principal;
import java.net.URI;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_AUTH_TOKEN;
import static eu.webeid.security.testutil.AbstractTestWithValidator.VALID_CHALLENGE_NONCE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

public class AuthTokenValidatorBuilderTest {

    // AuthTokenValidationConfiguration has a package-private constructor, but some tests need access to it outside its package.
    // Provide a public accessor to it for these tests.
    public static final AuthTokenValidationConfiguration CONFIGURATION = new AuthTokenValidationConfiguration();

    final AuthTokenValidatorBuilder builder = new AuthTokenValidatorBuilder();

    @Test
    void testOriginMissing() {
        assertThatThrownBy(builder::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("Origin URI must not be null");
    }

    @Test
    void testRootCertificateAuthorityMissing() {
        final AuthTokenValidatorBuilder builderWithMissingRootCa = builder
            .withSiteOrigin(URI.create("https://ria.ee"));
        assertThatThrownBy(builderWithMissingRootCa::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("At least one trusted certificate authority must be provided");
    }

    @Test
    void testValidatorOriginNotUrl() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("not-url"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testValidatorOriginExcessiveElements() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("https://ria.ee/excessive-element"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testValidatorOriginNotHttps() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("http://ria.ee"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void testValidatorOriginNotValidUrl() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("ria://ria.ee"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("Provided URI is not a valid URL");
    }

    @Test
    void testValidatorOriginNotValidSyntax() {
        assertThatThrownBy(() -> AuthTokenValidators.getAuthTokenValidator("https:///ria.ee"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("An URI syntax exception occurred");
    }

    @Test
    void whenRevocationCheckDisabledAndCustomCheckerConfigured_thenBuildFails() throws Exception {
        final AuthTokenValidatorBuilder builderWithRevocationDisabled = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withoutUserCertificateRevocationCheck()
            .withCertificateRevocationChecker(getNoopChecker());
        assertThatThrownBy(builderWithRevocationDisabled::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("User certificate revocation check is disabled, but a revocation checker was configured");
    }

    @Test
    void whenRevocationCheckDisabledAndPkixCheckerConfigured_thenBuildFails() throws Exception {
        final AuthTokenValidatorBuilder builderWithRevocationDisabled = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withoutUserCertificateRevocationCheck()
            .withPKIXRevocationChecker(mock(PKIXRevocationChecker.class));
        assertThatThrownBy(builderWithRevocationDisabled::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageStartingWith("User certificate revocation check is disabled, but a revocation checker was configured");
    }

    @Test
    void whenCustomCheckerAndPkixCheckerConfigured_thenBuildFails() throws Exception {
        final AuthTokenValidatorBuilder builderWithConflictingCheckers = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder()
            .withCertificateRevocationChecker(getNoopChecker())
            .withPKIXRevocationChecker(mock(PKIXRevocationChecker.class));
        assertThatThrownBy(builderWithConflictingCheckers::build)
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Do not combine withCertificateRevocationChecker(...) with withPKIXRevocationChecker(...).");
    }

    @Test
    void whenPlatformOcspNonceSettingChanges_thenBuiltValidatorsRetainTheirSetting() throws Exception {
        final AuthTokenValidatorBuilder configurableBuilder = AuthTokenValidators.getDefaultAuthTokenValidatorBuilder();
        final AuthTokenValidator defaultValidator = configurableBuilder.build();
        final AuthTokenValidator nonceDisabledValidator = configurableBuilder.withPlatformOcspNonceEnabled(false).build();
        final AuthTokenValidator nonceEnabledValidator = configurableBuilder.withPlatformOcspNonceEnabled(true).build();

        try (MockedStatic<CertificateValidator> certificateValidator = mockStatic(CertificateValidator.class)) {
            certificateValidator.when(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                    any(), anySet(), any(), any(), eq(RevocationMode.PLATFORM_OCSP), isNull(), isNull(), anyBoolean()
            )).thenReturn(List.of());

            for (AuthTokenValidator validator : List.of(defaultValidator, nonceDisabledValidator, nonceEnabledValidator)) {
                validator.validate(validator.parse(VALID_AUTH_TOKEN), VALID_CHALLENGE_NONCE);
            }

            certificateValidator.verify(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                    any(), anySet(), any(), any(), eq(RevocationMode.PLATFORM_OCSP), isNull(), isNull(), eq(true)
            ), times(2));
            certificateValidator.verify(() -> CertificateValidator.validateCertificateTrustAndRevocation(
                    any(), anySet(), any(), any(), eq(RevocationMode.PLATFORM_OCSP), isNull(), isNull(), eq(false)
            ));
        }
    }

    @Test
    void whenAllowedPoliciesAreEmpty_thenBuildUsesEsteidDefaults() throws Exception {
        final AuthTokenValidationConfiguration builtConfiguration = captureBuiltConfiguration(validBuilder());
        final Map<X500Principal, Set<ASN1ObjectIdentifier>> expectedPolicies =
            SubjectCertificatePolicies.ESTEID_PRODUCTION_DOCUMENT_POLICIES.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> Set.of(entry.getValue())));

        assertThat(builtConfiguration.getAllowedSubjectCertificatePolicies())
            .isEqualTo(expectedPolicies);
    }

    @Test
    void whenAllowedPoliciesAreConfigured_thenBuildUsesOnlyConfiguredPolicies() throws Exception {
        final X500Principal issuer = new X500Principal("CN=Example CA");
        final ASN1ObjectIdentifier policy = new ASN1ObjectIdentifier("1.2.3");

        final AuthTokenValidationConfiguration builtConfiguration = captureBuiltConfiguration(
            validBuilder().withAllowedCertificatePolicies(issuer, policy)
        );

        assertThat(builtConfiguration.getAllowedSubjectCertificatePolicies())
            .containsOnly(entry(issuer, Set.of(policy)));
    }

    @Test
    void whenOnlyEstonianAndEuCitizenIdCardsAreSupported_thenOnlyTheirPoliciesAreAllowed() throws Exception {
        final AuthTokenValidationConfiguration builtConfiguration = captureBuiltConfiguration(
            validBuilder()
                .withAllowedCertificatePolicies(
                    SubjectCertificatePolicies.ESTEID2018_ISSUER,
                    new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.1"),
                    new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.2")
                )
                .withAllowedCertificatePolicies(
                    SubjectCertificatePolicies.ESTEID2025_ISSUER,
                    new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.1"),
                    new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.2")
                )
        );

        assertThat(builtConfiguration.getAllowedSubjectCertificatePolicies())
            .containsOnly(
                entry(
                    SubjectCertificatePolicies.ESTEID2018_ISSUER,
                    Set.of(
                        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.1"),
                        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.2")
                    )
                ),
                entry(
                    SubjectCertificatePolicies.ESTEID2025_ISSUER,
                    Set.of(
                        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.1"),
                        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.2")
                    )
                )
            );
    }

    @Test
    @SuppressWarnings("deprecation")
    void whenDisallowedPoliciesAreConfiguredInMultipleCalls_thenPoliciesAreAdded() throws Exception {
        final ASN1ObjectIdentifier firstPolicy = new ASN1ObjectIdentifier("1.2.3");
        final ASN1ObjectIdentifier secondPolicy = new ASN1ObjectIdentifier("1.2.4");

        final AuthTokenValidationConfiguration builtConfiguration = captureBuiltConfiguration(
            validBuilder()
                .withDisallowedCertificatePolicies(firstPolicy)
                .withDisallowedCertificatePolicies(secondPolicy)
        );

        assertThat(builtConfiguration.getDisallowedSubjectCertificatePolicies())
            .containsExactlyInAnyOrder(firstPolicy, secondPolicy);
    }

    @Test
    @SuppressWarnings("deprecation")
    void whenAllowedAndDisallowedPoliciesAreConfigured_thenBuildFailsRegardlessOfCallOrder() {
        final X500Principal issuer = new X500Principal("CN=Example CA");
        final ASN1ObjectIdentifier allowedPolicy = new ASN1ObjectIdentifier("1.2.3");
        final ASN1ObjectIdentifier disallowedPolicy = new ASN1ObjectIdentifier("1.2.4");

        assertThatThrownBy(() -> validBuilder()
            .withAllowedCertificatePolicies(issuer, allowedPolicy)
            .withDisallowedCertificatePolicies(disallowedPolicy)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Certificate policy allow-list and deny-list cannot be enabled at the same time.");

        assertThatThrownBy(() -> validBuilder()
            .withDisallowedCertificatePolicies(disallowedPolicy)
            .withAllowedCertificatePolicies(issuer, allowedPolicy)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Certificate policy allow-list and deny-list cannot be enabled at the same time.");
    }

    private static AuthTokenValidationConfiguration captureBuiltConfiguration(
            AuthTokenValidatorBuilder builder) throws Exception {
        final AtomicReference<AuthTokenValidationConfiguration> capturedConfiguration = new AtomicReference<>();
        try (MockedConstruction<AuthTokenValidatorImpl> ignored = mockConstruction(
                AuthTokenValidatorImpl.class,
                (mock, context) -> capturedConfiguration.set(
                    (AuthTokenValidationConfiguration) context.arguments().get(0)
                ))) {
            builder.build();
        }
        return capturedConfiguration.get();
    }

    private static AuthTokenValidatorBuilder validBuilder() {
        return new AuthTokenValidatorBuilder()
            .withSiteOrigin(URI.create("https://ria.ee"))
            .withTrustedCertificateAuthorities(mock(X509Certificate.class));
    }

    private static CertificateRevocationChecker getNoopChecker() {
        return (subjectCertificate, issuerCertificate) -> List.of();
    }

}
