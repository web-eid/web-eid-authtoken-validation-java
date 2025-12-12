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
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

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

    private final X509Certificate certificate = mock(X509Certificate.class);
    private final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(Set.of());

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
}
