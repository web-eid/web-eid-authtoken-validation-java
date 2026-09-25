// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.UserCertificateParseException;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SubjectCertificatePolicyValidatorTest {

    private final X509Certificate certificate = mock(X509Certificate.class);
    private final SubjectCertificatePolicyValidator validator = new SubjectCertificatePolicyValidator(Set.of());

    @Test
    void whenPoliciesAreMissing_thenThrowsCertificateParseException() {
        assertThatThrownBy(() -> validator.validateCertificatePolicies(certificate))
                .isInstanceOf(UserCertificateParseException.class)
                .hasCauseInstanceOf(CertificateParsingException.class);
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
