// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.certvalidators;

import eu.webeid.security.exceptions.UserCertificateMissingPurposeException;
import eu.webeid.security.exceptions.UserCertificateWrongPurposeException;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SubjectCertificatePurposeValidatorTest {

    private static final String EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION = "1.3.6.1.5.5.7.3.2";
    private static final String EXTENDED_KEY_USAGE_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";
    // Key Usage bits: digitalSignature(0), keyAgreement(4).
    private static final boolean[] DIGITAL_SIGNATURE_KEY_USAGE = {true, false, false, false, false, false, false, false, false};
    private static final boolean[] KEY_AGREEMENT_KEY_USAGE = {false, false, false, false, true, false, false, false, false};

    private final X509Certificate certificate = mock(X509Certificate.class);

    @Test
    void whenDigitalSignatureKeyUsageIsRequiredAndPresent_thenValidationSucceeds() throws Exception {
        when(certificate.getKeyUsage()).thenReturn(DIGITAL_SIGNATURE_KEY_USAGE);
        when(certificate.getExtendedKeyUsage()).thenReturn(List.of(EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION));
        assertThatCode(() -> new SubjectCertificatePurposeValidator(true).validateCertificatePurpose(certificate))
            .doesNotThrowAnyException();
    }

    @Test
    void whenDigitalSignatureKeyUsageIsRequiredAndMissing_thenValidationFails() throws Exception {
        when(certificate.getKeyUsage()).thenReturn(KEY_AGREEMENT_KEY_USAGE);
        when(certificate.getExtendedKeyUsage()).thenReturn(List.of(EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION));
        assertThatExceptionOfType(UserCertificateWrongPurposeException.class)
            .isThrownBy(() -> new SubjectCertificatePurposeValidator(true).validateCertificatePurpose(certificate));
    }

    @Test
    void whenDigitalSignatureKeyUsageIsNotRequiredAndMissing_thenValidationSucceeds() throws Exception {
        when(certificate.getKeyUsage()).thenReturn(KEY_AGREEMENT_KEY_USAGE);
        when(certificate.getExtendedKeyUsage()).thenReturn(List.of(EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION));
        assertThatCode(() -> new SubjectCertificatePurposeValidator(false).validateCertificatePurpose(certificate))
            .doesNotThrowAnyException();
    }

    @Test
    void whenDigitalSignatureKeyUsageIsNotRequiredAndKeyUsageExtensionIsMissing_thenValidationFails() {
        when(certificate.getKeyUsage()).thenReturn(null);
        assertThatExceptionOfType(UserCertificateMissingPurposeException.class)
            .isThrownBy(() -> new SubjectCertificatePurposeValidator(false).validateCertificatePurpose(certificate));
    }

    @Test
    void whenDigitalSignatureKeyUsageIsNotRequiredAndClientAuthenticationIsMissing_thenValidationFails() throws Exception {
        when(certificate.getKeyUsage()).thenReturn(KEY_AGREEMENT_KEY_USAGE);
        when(certificate.getExtendedKeyUsage()).thenReturn(List.of(EXTENDED_KEY_USAGE_EMAIL_PROTECTION));
        assertThatExceptionOfType(UserCertificateWrongPurposeException.class)
            .isThrownBy(() -> new SubjectCertificatePurposeValidator(false).validateCertificatePurpose(certificate));
    }

}
