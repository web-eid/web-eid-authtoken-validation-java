// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.testutil;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

public final class TestCertificateBuilder {

    private static final KeyPair TEST_KEY_PAIR = generateKeyPair();

    public static X509Certificate buildCertificate(Extension... extensions) throws Exception {
        final X500Name name = new X500Name("CN=Test OCSP Responder");
        final Instant now = Instant.now();
        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            name, BigInteger.ONE, Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(3600)),
            name, TEST_KEY_PAIR.getPublic());
        for (final Extension extension : extensions) {
            builder.addExtension(extension);
        }
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(TEST_KEY_PAIR.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static KeyPair generateKeyPair() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private TestCertificateBuilder() {
        throw new IllegalStateException("Utility class");
    }
}
