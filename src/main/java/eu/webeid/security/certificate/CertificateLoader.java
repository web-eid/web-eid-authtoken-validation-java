// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
