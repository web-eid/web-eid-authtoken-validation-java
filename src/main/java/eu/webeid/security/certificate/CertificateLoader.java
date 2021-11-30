/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static eu.webeid.security.util.Base64Decoder.decodeBase64;

public final class CertificateLoader {

    public static X509Certificate[] loadCertificatesFromResources(String... resourceNames) throws CertificateException, IOException {
        final List<X509Certificate> caCertificates = new ArrayList<>();
        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        for (final String resourceName : resourceNames) {
            try (final InputStream resourceAsStream = ClassLoader.getSystemResourceAsStream(resourceName)) {
                X509Certificate caCertificate = (X509Certificate) certFactory.generateCertificate(resourceAsStream);
                caCertificates.add(caCertificate);
            }
        }

        return caCertificates.toArray(new X509Certificate[0]);
    }

    public static X509Certificate decodeCertificateFromBase64(String certificateInBase64) throws CertificateDecodingException {
        Objects.requireNonNull(certificateInBase64, "certificateInBase64");
        try (final InputStream targetStream = new ByteArrayInputStream(decodeBase64(certificateInBase64))) {
            return (X509Certificate) CertificateFactory
                .getInstance("X509")
                .generateCertificate(targetStream);
        } catch (IOException | CertificateException | IllegalArgumentException e) {
            throw new CertificateDecodingException(e);
        }
    }

    private CertificateLoader() {
        throw new IllegalStateException("Utility class");
    }
}
