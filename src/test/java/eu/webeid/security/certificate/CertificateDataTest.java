package eu.webeid.security.certificate;

import org.junit.jupiter.api.Test;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static eu.webeid.security.testutil.Certificates.getOrganizationCert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateDataTest {

    @Test
    void whenOrganizationCertificate_thenSubjectCNAndIdCodeAndCountryCodeExtractionSucceeds() throws Exception {
        final X509Certificate organizationCert = getOrganizationCert();

        assertThat(CertificateData.getSubjectCN(organizationCert))
            .isEqualTo("Testijad.ee isikutuvastus");
        assertThat(CertificateData.getSubjectIdCode(organizationCert))
            .isEqualTo("12276279");
        assertThat(CertificateData.getSubjectCountryCode(organizationCert))
            .isEqualTo("EE");
    }

    @Test
    void whenOrganizationCertificate_thenSubjectGivenNameAndSurnameExtractionFails() throws Exception {
        final X509Certificate organizationCert = getOrganizationCert();

        assertThatThrownBy(() -> CertificateData.getSubjectGivenName(organizationCert))
            .isInstanceOf(CertificateEncodingException.class)
            .hasMessage("X500 name RDNs empty or first element is null");
        assertThatThrownBy(() -> CertificateData.getSubjectSurname(organizationCert))
            .isInstanceOf(CertificateEncodingException.class)
            .hasMessage("X500 name RDNs empty or first element is null");
    }

}
