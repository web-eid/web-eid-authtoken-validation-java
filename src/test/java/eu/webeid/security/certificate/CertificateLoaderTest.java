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

package eu.webeid.security.certificate;

import eu.webeid.security.exceptions.CertificateDecodingException;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static eu.webeid.security.testutil.Certificates.getJaakKristjanEsteid2018Cert;
import static eu.webeid.security.testutil.Certificates.getMariliisEsteid2015Cert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class CertificateLoaderTest {

    @Test
    void whenNullList_thenReturnsEmptyList() throws Exception {
        assertThat(CertificateLoader.decodeCertificatesFromBase64(null))
            .isEmpty();
    }

    @Test
    void whenEmptyList_thenReturnsEmptyList() throws Exception {
        assertThat(CertificateLoader.decodeCertificatesFromBase64(List.of()))
            .isEmpty();
    }

    @Test
    void whenValidBase64Certificates_thenDecodesAll() throws Exception {
        final X509Certificate firstCert = getJaakKristjanEsteid2018Cert();
        final X509Certificate secondCert = getMariliisEsteid2015Cert();

        final List<X509Certificate> decoded = CertificateLoader.decodeCertificatesFromBase64(
            List.of(toBase64(firstCert), toBase64(secondCert)));

        assertThat(decoded)
            .containsExactly(firstCert, secondCert);
    }

    @Test
    void whenNotBase64_thenThrows() {
        assertThatExceptionOfType(CertificateDecodingException.class)
            .isThrownBy(() -> CertificateLoader.decodeCertificatesFromBase64(List.of("not base64!")));
    }

    @Test
    void whenBase64ButNotACertificate_thenThrows() {
        final String notACertificate = Base64.getEncoder().encodeToString("this is not a certificate".getBytes());
        assertThatExceptionOfType(CertificateDecodingException.class)
            .isThrownBy(() -> CertificateLoader.decodeCertificatesFromBase64(List.of(notACertificate)));
    }

    private static String toBase64(X509Certificate certificate) throws Exception {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }
}
