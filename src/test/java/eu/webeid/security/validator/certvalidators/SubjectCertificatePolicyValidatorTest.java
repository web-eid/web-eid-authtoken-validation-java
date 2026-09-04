// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.UserCertificateDisallowedPolicyException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

import java.util.List;

import static eu.webeid.security.testutil.Certificates.getCertificateWithoutCertificatePolicies;
import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class SubjectCertificatePolicyValidatorTest {

    private static final ASN1ObjectIdentifier ESTEID2018_POLICY = new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.1");
    private static final ASN1ObjectIdentifier UNRELATED_POLICY = new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.2");

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
    void whenCertificateDoesNotContainCertificatePoliciesExtension_thenValidationSucceeds() throws Exception {
        final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(List.of(ESTEID2018_POLICY));
        assertThatCode(() -> validator.validateCertificatePolicies(getCertificateWithoutCertificatePolicies()))
            .doesNotThrowAnyException();
    }

}
