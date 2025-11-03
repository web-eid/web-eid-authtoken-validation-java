/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

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
