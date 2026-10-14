// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import eu.webeid.security.exceptions.UserCertificateParseException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import static eu.webeid.security.testutil.Certificates.getCertificateWithoutCertificatePolicies;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SubjectCertificatePolicyValidatorTest {

    private static final ASN1ObjectIdentifier ESTEID2018_POLICY = new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.1");
    private static final ASN1ObjectIdentifier UNRELATED_POLICY = new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.2");
    private static final X500Principal ESTEID2018_TEST_ISSUER = new X500Principal(
        "CN=TEST of ESTEID2018,2.5.4.97=#0c0e4e545245452d3130373437303133,O=SK ID Solutions AS,C=EE"
    );

    private final X509Certificate certificate = mock(X509Certificate.class);
    private final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(Set.of());

    @BeforeEach
    void setUpCertificateIssuer() {
        when(certificate.getIssuerX500Principal()).thenReturn(new X500Principal("CN=Unconfigured CA"));
    }

    @Test
    void whenCertificateContainsDisallowedPolicy_thenValidationFails() throws Exception {
        final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(List.of(ESTEID2018_POLICY));
        assertThatExceptionOfType(UserCertificateDisallowedPolicyException.class)
            .isThrownBy(() -> validator.validateCertificatePolicies(getJaakKristjanEsteid2018Cert()));
    }

    @Test
    void whenCertificateDoesNotContainDisallowedPolicies_thenValidationSucceeds() throws Exception {
        final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(List.of(UNRELATED_POLICY));
        assertThatCode(() -> validator.validateCertificatePolicies(getJaakKristjanEsteid2018Cert()))
            .doesNotThrowAnyException();
    }

    @Test
    void whenCertificateContainsAllowedPolicy_thenValidationSucceeds() throws Exception {
        final SubjectCertificatePolicyValidator validator =
            new SubjectCertificatePolicyValidator(allowedPolicies(ESTEID2018_POLICY), Set.of());
        assertThatCode(() -> validator.validateCertificatePolicies(getJaakKristjanEsteid2018Cert()))
            .doesNotThrowAnyException();
    }

    @Test
    void whenCertificateDoesNotContainAllowedPolicy_thenValidationFails() throws Exception {
        final SubjectCertificatePolicyValidator validator =
            new SubjectCertificatePolicyValidator(allowedPolicies(UNRELATED_POLICY), Set.of());
        assertThatExceptionOfType(UserCertificateDisallowedPolicyException.class)
            .isThrownBy(() -> validator.validateCertificatePolicies(getJaakKristjanEsteid2018Cert()));
    }

    @Test
    void whenPolicyIsBothAllowedAndDisallowed_thenAllowListTakesPrecedence() throws Exception {
        final SubjectCertificatePolicyValidator validator =
            new SubjectCertificatePolicyValidator(
                allowedPolicies(ESTEID2018_POLICY),
                List.of(ESTEID2018_POLICY)
            );
        assertThatCode(() -> validator.validateCertificatePolicies(getJaakKristjanEsteid2018Cert()))
            .doesNotThrowAnyException();
    }

    @Test
    void whenIssuerHasNoAllowListEntry_thenValidationFallsBackToDisallowedPolicies() throws Exception {
        final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(
            Map.of(new X500Principal("CN=Another CA"), Set.of(ESTEID2018_POLICY)),
            List.of(ESTEID2018_POLICY)
        );

        assertThatExceptionOfType(UserCertificateDisallowedPolicyException.class)
            .isThrownBy(() -> validator.validateCertificatePolicies(getJaakKristjanEsteid2018Cert()));
    }

    @Test
    void whenIssuerAllowListIsEmpty_thenValidationFallsBackToDisallowedPolicies() throws Exception {
        final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(
            Map.of(ESTEID2018_TEST_ISSUER, Set.of()),
            List.of(ESTEID2018_POLICY)
        );

        assertThatExceptionOfType(UserCertificateDisallowedPolicyException.class)
            .isThrownBy(() -> validator.validateCertificatePolicies(getJaakKristjanEsteid2018Cert()));
    }

    @Test
    void whenCertificateDoesNotContainCertificatePoliciesExtension_thenValidationSucceeds() throws Exception {
        final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(List.of(ESTEID2018_POLICY));
        assertThatCode(() -> validator.validateCertificatePolicies(getCertificateWithoutCertificatePolicies()))
            .doesNotThrowAnyException();
    }

    @Test
    void whenAllowListIsConfiguredAndCertificatePoliciesExtensionIsMissing_thenValidationFails() throws Exception {
        when(certificate.getIssuerX500Principal())
            .thenReturn(ESTEID2018_TEST_ISSUER);
        final SubjectCertificatePolicyValidator validator =
            new SubjectCertificatePolicyValidator(allowedPolicies(ESTEID2018_POLICY), Set.of());
        assertThatExceptionOfType(UserCertificateDisallowedPolicyException.class)
            .isThrownBy(() -> validator.validateCertificatePolicies(certificate));
    }

    @Test
    void whenPoliciesHaveInvalidEncoding_thenPreservesParsingFailure() {
        when(certificate.getExtensionValue(Extension.certificatePolicies.getId())).thenReturn(new byte[] {4, 2, 4, 5});

        assertThatThrownBy(() -> validator.validateCertificatePolicies(certificate))
                .isInstanceOf(UserCertificateParseException.class)
                .hasCauseExactlyInstanceOf(ASN1Exception.class);
    }

    @Test
    void whenPoliciesValueIsEmpty_thenThrowsCertificateParseException() throws Exception {
        when(certificate.getExtensionValue(Extension.certificatePolicies.getId()))
                .thenReturn(new DEROctetString(new byte[0]).getEncoded());

        assertThatThrownBy(() -> validator.validateCertificatePolicies(certificate))
                .isInstanceOf(UserCertificateParseException.class)
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void whenPoliciesHaveWrongAsn1Type_thenPreservesParsingFailure() throws Exception {
        when(certificate.getExtensionValue(Extension.certificatePolicies.getId()))
                .thenReturn(new DEROctetString(new ASN1Integer(1)).getEncoded());

        assertThatThrownBy(() -> validator.validateCertificatePolicies(certificate))
                .isInstanceOf(UserCertificateParseException.class)
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    private static Map<X500Principal, Set<ASN1ObjectIdentifier>> allowedPolicies(
            ASN1ObjectIdentifier... policies) {
        return Map.of(ESTEID2018_TEST_ISSUER, Set.of(policies));
    }
}
