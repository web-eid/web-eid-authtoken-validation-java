package eu.webeid.security.certificate;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static eu.webeid.security.testutil.Certificates.getOrganizationCert;
import static org.assertj.core.api.Assertions.assertThat;

class CertificateDataTest {

    @Test
    void whenOrganizationCertificate_thenSubjectCNAndIdCodeAndCountryCodeExtractionSucceeds() throws Exception {
        final X509Certificate organizationCert = getOrganizationCert();

        assertThat(CertificateData.getSubjectCN(organizationCert).orElseThrow())
            .isEqualTo("Testijad.ee isikutuvastus");
        assertThat(CertificateData.getSubjectIdCode(organizationCert).orElseThrow())
            .isEqualTo("12276279");
        assertThat(CertificateData.getSubjectCountryCode(organizationCert).orElseThrow())
            .isEqualTo("EE");
    }

    @Test
    void whenOrganizationCertificate_thenSubjectGivenNameAndSurnameAreEmpty() throws Exception {
        final X509Certificate organizationCert = getOrganizationCert();

        assertThat(CertificateData.getSubjectGivenName(organizationCert))
            .isEmpty();
        assertThat(CertificateData.getSubjectSurname(organizationCert))
            .isEmpty();
    }

}
