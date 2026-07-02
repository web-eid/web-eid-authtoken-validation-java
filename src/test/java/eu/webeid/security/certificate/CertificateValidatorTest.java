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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateValidatorTest {

    private static final Date NOW = new Date();
    private static final Date NOT_BEFORE = new Date(NOW.getTime() - 86_400_000L);
    private static final Date NOT_AFTER = new Date(NOW.getTime() + 86_400_000L);

    private static X509Certificate rootCertificate;
    private static X509Certificate intermediateCertificateC; // signed by root
    private static X509Certificate intermediateCertificateB; // signed by C
    private static X509Certificate intermediateCertificateA; // signed by B, direct issuer of the leaf
    private static X509Certificate leafCertificate;          // signed by A

    @BeforeAll
    static void setUp() throws Exception {
        // A single chain: root -> intermediateCertificateC -> intermediateCertificateB -> intermediateCertificateA -> leaf.
        final KeyPair rootKeyPair = generateKeyPair();
        final KeyPair intermediateCKeyPair = generateKeyPair();
        final KeyPair intermediateBKeyPair = generateKeyPair();
        final KeyPair intermediateAKeyPair = generateKeyPair();
        final KeyPair leafKeyPair = generateKeyPair();

        final X500Name rootName = new X500Name("CN=Test Root CA");
        final X500Name intermediateCName = new X500Name("CN=Test Intermediate CA C");
        final X500Name intermediateBName = new X500Name("CN=Test Intermediate CA B");
        final X500Name intermediateAName = new X500Name("CN=Test Intermediate CA A");
        final X500Name leafName = new X500Name("CN=Test Leaf");

        rootCertificate = generateCertificate(rootName, rootKeyPair.getPublic(),
            rootName, rootKeyPair.getPrivate(), rootKeyPair.getPublic(), true, BigInteger.valueOf(1));
        intermediateCertificateC = generateCertificate(intermediateCName, intermediateCKeyPair.getPublic(),
            rootName, rootKeyPair.getPrivate(), rootKeyPair.getPublic(), true, BigInteger.valueOf(2));
        intermediateCertificateB = generateCertificate(intermediateBName, intermediateBKeyPair.getPublic(),
            intermediateCName, intermediateCKeyPair.getPrivate(), intermediateCKeyPair.getPublic(), true, BigInteger.valueOf(3));
        intermediateCertificateA = generateCertificate(intermediateAName, intermediateAKeyPair.getPublic(),
            intermediateBName, intermediateBKeyPair.getPrivate(), intermediateBKeyPair.getPublic(), true, BigInteger.valueOf(4));
        leafCertificate = generateCertificate(leafName, leafKeyPair.getPublic(),
            intermediateAName, intermediateAKeyPair.getPrivate(), intermediateAKeyPair.getPublic(), false, BigInteger.valueOf(5));
    }

    @Test
    void whenChainHasIntermediate_thenReturnsDirectIssuerNotTrustAnchor() throws Exception {
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCertificate, null));
        final CertStore certStore = CertificateValidator.buildCertStoreFromCertificates(
            Arrays.asList(intermediateCertificateA, intermediateCertificateB, intermediateCertificateC));

        final X509Certificate issuer = CertificateValidator.validateIsSignedByTrustedCA(
            leafCertificate, anchors, certStore, NOW);

        // The leaf is issued by intermediate A, whose chain (A -> B -> C) leads to the root trust anchor. The issuer
        // used for OCSP must be the direct issuer (intermediate A), not the trust anchor (the root).
        assertThat(issuer).isEqualTo(intermediateCertificateA);
    }

    @Test
    void whenSubjectIssuedDirectlyByTrustAnchor_thenReturnsTrustAnchor() throws Exception {
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(intermediateCertificateA, null));
        final CertStore emptyStore = CertificateValidator.buildCertStoreFromCertificates(Collections.emptyList());

        final X509Certificate issuer = CertificateValidator.validateIsSignedByTrustedCA(
            leafCertificate, anchors, emptyStore, NOW);

        // Single-hop chain: the direct issuer is the trust anchor itself.
        assertThat(issuer).isEqualTo(intermediateCertificateA);
    }

    private static KeyPair generateKeyPair() throws Exception {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate generateCertificate(X500Name subject, PublicKey subjectPublicKey,
                                                       X500Name issuer, PrivateKey issuerPrivateKey, PublicKey issuerPublicKey,
                                                       boolean ca, BigInteger serial) throws Exception {
        final JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer, serial, NOT_BEFORE, NOT_AFTER, subject, subjectPublicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(subjectPublicKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(issuerPublicKey));
        if (ca) {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
