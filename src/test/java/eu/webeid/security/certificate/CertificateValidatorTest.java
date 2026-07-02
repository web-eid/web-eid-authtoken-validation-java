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

import eu.webeid.security.certificate.CertificateValidator.IntermediateRevocationCheck;
import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotTrustedException;
import eu.webeid.security.exceptions.JceException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.MockedStatic;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class CertificateValidatorTest {

    private static final Date NOW = new Date();
    private static final Date NOT_BEFORE = new Date(NOW.getTime() - 86_400_000L);
    private static final Date NOT_AFTER = new Date(NOW.getTime() + 86_400_000L);

    private static X509Certificate rootCertificate;
    private static X509Certificate intermediateCertificateC; // signed by root
    private static X509Certificate intermediateCertificateB; // signed by C
    private static X509Certificate intermediateCertificateA; // signed by B, direct issuer of the leaf
    private static X509Certificate leafCertificate;          // signed by A
    private static X509CRL rootCrl;
    private static X509CRL intermediateCCrl;
    private static X509CRL intermediateBCrl;
    private static X509CRL intermediateBRevokingACrl;

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

        rootCrl = generateCrl(rootName, rootKeyPair.getPrivate());
        intermediateCCrl = generateCrl(intermediateCName, intermediateCKeyPair.getPrivate());
        intermediateBCrl = generateCrl(intermediateBName, intermediateBKeyPair.getPrivate());
        intermediateBRevokingACrl = generateCrl(
            intermediateBName, intermediateBKeyPair.getPrivate(), intermediateCertificateA.getSerialNumber());
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

    @Test
    void whenChainHasTokenSuppliedIntermediates_thenReturnsDirectIssuerNotTrustAnchor() throws Exception {
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCertificate, null));
        final CertStore crlStore = buildCrlStore(rootCrl, intermediateCCrl, intermediateBCrl);

        final X509Certificate issuer = CertificateValidator.validateIsSignedByTrustedCA(
            leafCertificate, "User", anchors, crlStore,
            List.of(intermediateCertificateA, intermediateCertificateB, intermediateCertificateC),
            IntermediateRevocationCheck.ENABLED, NOW);

        // The leaf is issued by intermediate A, whose chain (A -> B -> C) leads to the root trust anchor. The issuer
        // used for OCSP must be the direct issuer (intermediate A), not the trust anchor (the root).
        assertThat(issuer).isEqualTo(intermediateCertificateA);
    }

    @Test
    void whenChainHasMultipleTokenSuppliedIntermediatesAndGrandparentIsPinned_thenValidationSucceeds() throws Exception {
        // The token supplies the full A -> B -> C intermediate chain and the top (C) is configured as the trust
        // anchor. The path builds leaf -> A -> B, and the issuer returned for OCSP is the direct issuer (A).
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(intermediateCertificateC, null));
        final CertStore crlStore = buildCrlStore(intermediateCCrl, intermediateBCrl);

        final X509Certificate issuer = CertificateValidator.validateIsSignedByTrustedCA(
            leafCertificate, "User", anchors, crlStore,
            List.of(intermediateCertificateA, intermediateCertificateB, intermediateCertificateC),
            IntermediateRevocationCheck.ENABLED, NOW);

        assertThat(issuer).isEqualTo(intermediateCertificateA);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void whenNoTokenSuppliedIntermediatesAndChainBuiltFromTrustedStore_thenIntermediateRevocationCheckSucceeds(
        List<X509Certificate> additionalIntermediateCertificates) throws Exception {
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCertificate, null));
        final CertStore trustedStoreWithCrls = buildCertificateAndCrlStore(
            List.of(intermediateCertificateA, intermediateCertificateB, intermediateCertificateC),
            List.of(rootCrl, intermediateCCrl, intermediateBCrl));

        final X509Certificate issuer = CertificateValidator.validateIsSignedByTrustedCA(
            leafCertificate, "User", anchors, trustedStoreWithCrls,
            additionalIntermediateCertificates,
            IntermediateRevocationCheck.ENABLED, NOW);

        assertThat(issuer).isEqualTo(intermediateCertificateA);
    }

    @Test
    void whenTokenSuppliedIntermediateIsRevoked_thenRejectsCertificateChain() throws Exception {
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCertificate, null));
        final CertStore crlStore = buildCrlStore(rootCrl, intermediateCCrl, intermediateBRevokingACrl);

        assertThatThrownBy(() -> CertificateValidator.validateIsSignedByTrustedCA(
            leafCertificate, "User", anchors, crlStore,
            List.of(intermediateCertificateA, intermediateCertificateB, intermediateCertificateC),
            IntermediateRevocationCheck.ENABLED, NOW))
            .isInstanceOf(CertificateNotTrustedException.class)
            // The exception names the offending intermediate, not the leaf.
            .hasMessage("Certificate CN=Test Intermediate CA A is not trusted")
            .satisfies(exception -> {
                final CertPathValidatorException validationException =
                    (CertPathValidatorException) exception.getCause();
                assertThat(validationException.getReason())
                    .isEqualTo(CertPathValidatorException.BasicReason.REVOKED);
            });
    }

    @Test
    void whenTokenSuppliedIntermediateRevocationStatusIsUnknown_thenRejectsCertificateChain() throws Exception {
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCertificate, null));
        final CertStore emptyStore = CertificateValidator.buildCertStoreFromCertificates(Collections.emptyList());

        assertThatThrownBy(() -> CertificateValidator.validateIsSignedByTrustedCA(
            leafCertificate, "User", anchors, emptyStore,
            List.of(intermediateCertificateA, intermediateCertificateB, intermediateCertificateC),
            IntermediateRevocationCheck.ENABLED, NOW))
            .isInstanceOf(CertificateNotTrustedException.class)
            .hasCauseInstanceOf(CertPathValidatorException.class);
    }

    @Test
    void whenRevocationFailureDoesNotIdentifyCertificate_thenReportsLeafCertificate() throws Exception {
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCertificate, null));
        final CertStore crlStore = buildCrlStore(rootCrl, intermediateCCrl, intermediateBCrl);
        final String validatorType = CertPathValidator.getDefaultType();
        final CertPathValidator certPathValidator = mock(CertPathValidator.class);
        final PKIXRevocationChecker revocationChecker = mock(PKIXRevocationChecker.class);
        when(certPathValidator.getRevocationChecker()).thenReturn(revocationChecker);
        when(certPathValidator.validate(any(CertPath.class), any(PKIXParameters.class)))
            .thenThrow(new CertPathValidatorException("Revocation failure without certificate index"));

        try (MockedStatic<CertPathValidator> mockedValidator = mockStatic(CertPathValidator.class)) {
            mockedValidator.when(CertPathValidator::getDefaultType)
                .thenReturn(validatorType);
            mockedValidator.when(() -> CertPathValidator.getInstance(validatorType))
                .thenReturn(certPathValidator);

            assertThatThrownBy(() -> CertificateValidator.validateIsSignedByTrustedCA(
                leafCertificate, "User", anchors, crlStore,
                List.of(intermediateCertificateA, intermediateCertificateB, intermediateCertificateC),
                IntermediateRevocationCheck.ENABLED, NOW))
                .isInstanceOf(CertificateNotTrustedException.class)
                .hasMessage("Certificate CN=Test Leaf is not trusted")
                .hasCauseInstanceOf(CertPathValidatorException.class);
        }
    }

    @Test
    void whenRevocationValidatorIsUnavailable_thenWrapsFailureAsJceException() throws Exception {
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCertificate, null));
        final CertStore crlStore = buildCrlStore(rootCrl, intermediateCCrl, intermediateBCrl);
        final String validatorType = CertPathValidator.getDefaultType();
        final NoSuchAlgorithmException cause = new NoSuchAlgorithmException("PKIX validator unavailable");

        try (MockedStatic<CertPathValidator> mockedValidator = mockStatic(CertPathValidator.class)) {
            mockedValidator.when(CertPathValidator::getDefaultType)
                .thenReturn(validatorType);
            mockedValidator.when(() -> CertPathValidator.getInstance(validatorType))
                .thenThrow(cause);

            assertThatExceptionOfType(JceException.class)
                .isThrownBy(() -> CertificateValidator.validateIsSignedByTrustedCA(
                    leafCertificate, "User", anchors, crlStore,
                    List.of(intermediateCertificateA, intermediateCertificateB, intermediateCertificateC),
                    IntermediateRevocationCheck.ENABLED, NOW))
                .withMessage("Java Cryptography Extension loading or configuration failed")
                .withCause(cause);
        }
    }

    @Test
    void whenCertificateExpired_thenMessageUsesProvidedSubject() throws Exception {
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(intermediateCertificateA, null));
        final CertStore emptyStore = CertificateValidator.buildCertStoreFromCertificates(Collections.emptyList());
        final Date afterExpiry = new Date(NOT_AFTER.getTime() + 86_400_000L);

        assertThatExceptionOfType(CertificateExpiredException.class)
            .isThrownBy(() -> CertificateValidator.validateIsSignedByTrustedCA(
                leafCertificate, "Signing", anchors, emptyStore, Collections.emptyList(),
                IntermediateRevocationCheck.DISABLED, afterExpiry))
            .withMessage("Signing certificate has expired");
    }

    @Test
    void whenTokenSuppliedChainTerminatesAtUntrustedRoot_thenRejectsCertificateChain() throws Exception {
        // The token supplies a complete, internally consistent chain whose self-signed root is not a configured
        // trust anchor. Token-supplied certificates are certification-path candidates only, never trust anchors,
        // so the chain must be rejected even though every signature in it verifies.
        final KeyPair rogueRootKeyPair = generateKeyPair();
        final KeyPair rogueIntermediateKeyPair = generateKeyPair();
        final X500Name rogueRootName = new X500Name("CN=Rogue Root CA");
        final X500Name rogueIntermediateName = new X500Name("CN=Rogue Intermediate CA");
        final X509Certificate rogueRootCertificate = generateCertificate(rogueRootName, rogueRootKeyPair.getPublic(),
            rogueRootName, rogueRootKeyPair.getPrivate(), rogueRootKeyPair.getPublic(), true, BigInteger.valueOf(100));
        final X509Certificate rogueIntermediateCertificate = generateCertificate(
            rogueIntermediateName, rogueIntermediateKeyPair.getPublic(),
            rogueRootName, rogueRootKeyPair.getPrivate(), rogueRootKeyPair.getPublic(), true, BigInteger.valueOf(101));
        final X509Certificate rogueLeafCertificate = generateCertificate(
            new X500Name("CN=Rogue Leaf"), generateKeyPair().getPublic(),
            rogueIntermediateName, rogueIntermediateKeyPair.getPrivate(), rogueIntermediateKeyPair.getPublic(),
            false, BigInteger.valueOf(102));

        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCertificate, null));
        final CertStore emptyStore = CertificateValidator.buildCertStoreFromCertificates(Collections.emptyList());

        assertThatThrownBy(() -> CertificateValidator.validateIsSignedByTrustedCA(
            rogueLeafCertificate, "User", anchors, emptyStore,
            List.of(rogueIntermediateCertificate, rogueRootCertificate),
            IntermediateRevocationCheck.ENABLED, NOW))
            .isInstanceOf(CertificateNotTrustedException.class)
            .hasMessage("Certificate CN=Rogue Leaf is not trusted")
            .hasCauseInstanceOf(CertPathBuilderException.class);
    }

    @Test
    void whenTokenSuppliedIntermediateIsExpired_thenRejectsCertificateChain() throws Exception {
        // Only the token-supplied intermediate is outside its validity window; the leaf itself is currently valid.
        final KeyPair localRootKeyPair = generateKeyPair();
        final KeyPair expiredIntermediateKeyPair = generateKeyPair();
        final X500Name localRootName = new X500Name("CN=Local Root CA");
        final X500Name expiredIntermediateName = new X500Name("CN=Expired Intermediate CA");
        final X509Certificate localRootCertificate = generateCertificate(localRootName, localRootKeyPair.getPublic(),
            localRootName, localRootKeyPair.getPrivate(), localRootKeyPair.getPublic(), true, BigInteger.valueOf(110));
        final X509Certificate expiredIntermediateCertificate = generateCertificate(
            expiredIntermediateName, expiredIntermediateKeyPair.getPublic(),
            localRootName, localRootKeyPair.getPrivate(), localRootKeyPair.getPublic(), true, BigInteger.valueOf(111),
            new Date(NOW.getTime() - 172_800_000L), new Date(NOW.getTime() - 86_400_000L));
        final X509Certificate currentLeafCertificate = generateCertificate(
            new X500Name("CN=Current Leaf"), generateKeyPair().getPublic(),
            expiredIntermediateName, expiredIntermediateKeyPair.getPrivate(), expiredIntermediateKeyPair.getPublic(),
            false, BigInteger.valueOf(112));

        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(localRootCertificate, null));
        final CertStore emptyStore = CertificateValidator.buildCertStoreFromCertificates(Collections.emptyList());

        assertThatThrownBy(() -> CertificateValidator.validateIsSignedByTrustedCA(
            currentLeafCertificate, "User", anchors, emptyStore,
            List.of(expiredIntermediateCertificate),
            IntermediateRevocationCheck.ENABLED, NOW))
            .isInstanceOf(CertificateNotTrustedException.class);
    }

    @Test
    void whenTokenSuppliedIntermediateIsNotYetValid_thenRejectsCertificateChain() throws Exception {
        // Only the token-supplied intermediate is outside its validity window; the leaf itself is currently valid.
        final KeyPair localRootKeyPair = generateKeyPair();
        final KeyPair notYetValidIntermediateKeyPair = generateKeyPair();
        final X500Name localRootName = new X500Name("CN=Local Root CA");
        final X500Name notYetValidIntermediateName = new X500Name("CN=Not Yet Valid Intermediate CA");
        final X509Certificate localRootCertificate = generateCertificate(localRootName, localRootKeyPair.getPublic(),
            localRootName, localRootKeyPair.getPrivate(), localRootKeyPair.getPublic(), true, BigInteger.valueOf(113));
        final X509Certificate notYetValidIntermediateCertificate = generateCertificate(
            notYetValidIntermediateName, notYetValidIntermediateKeyPair.getPublic(),
            localRootName, localRootKeyPair.getPrivate(), localRootKeyPair.getPublic(), true, BigInteger.valueOf(114),
            new Date(NOW.getTime() + 86_400_000L), new Date(NOW.getTime() + 172_800_000L));
        final X509Certificate currentLeafCertificate = generateCertificate(
            new X500Name("CN=Current Leaf"), generateKeyPair().getPublic(),
            notYetValidIntermediateName, notYetValidIntermediateKeyPair.getPrivate(), notYetValidIntermediateKeyPair.getPublic(),
            false, BigInteger.valueOf(115));

        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(localRootCertificate, null));
        final CertStore emptyStore = CertificateValidator.buildCertStoreFromCertificates(Collections.emptyList());

        assertThatThrownBy(() -> CertificateValidator.validateIsSignedByTrustedCA(
            currentLeafCertificate, "User", anchors, emptyStore,
            List.of(notYetValidIntermediateCertificate),
            IntermediateRevocationCheck.ENABLED, NOW))
            .isInstanceOf(CertificateNotTrustedException.class);
    }

    @Test
    void whenTrustAnchorIsExpired_thenThrowsCertificateExpiredException() throws Exception {
        // The trust anchor is not part of the built certification path, so PKIX path validation does not check its
        // validity; the explicit anchor validity check must reject it while the leaf itself is currently valid.
        final KeyPair expiredRootKeyPair = generateKeyPair();
        final X500Name expiredRootName = new X500Name("CN=Expired Root CA");
        final X509Certificate expiredRootCertificate = generateCertificate(
            expiredRootName, expiredRootKeyPair.getPublic(),
            expiredRootName, expiredRootKeyPair.getPrivate(), expiredRootKeyPair.getPublic(), true, BigInteger.valueOf(116),
            new Date(NOW.getTime() - 172_800_000L), new Date(NOW.getTime() - 86_400_000L));
        final X509Certificate currentLeafCertificate = generateCertificate(
            new X500Name("CN=Current Leaf"), generateKeyPair().getPublic(),
            expiredRootName, expiredRootKeyPair.getPrivate(), expiredRootKeyPair.getPublic(),
            false, BigInteger.valueOf(117));

        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(expiredRootCertificate, null));
        final CertStore emptyStore = CertificateValidator.buildCertStoreFromCertificates(Collections.emptyList());

        assertThatExceptionOfType(CertificateExpiredException.class)
            .isThrownBy(() -> CertificateValidator.validateIsSignedByTrustedCA(
                currentLeafCertificate, "User", anchors, emptyStore, Collections.emptyList(),
                IntermediateRevocationCheck.DISABLED, NOW))
            .withMessage("Trusted CA certificate has expired");
    }

    private static KeyPair generateKeyPair() throws Exception {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate generateCertificate(X500Name subject, PublicKey subjectPublicKey,
                                                       X500Name issuer, PrivateKey issuerPrivateKey, PublicKey issuerPublicKey,
                                                       boolean ca, BigInteger serial) throws Exception {
        return generateCertificate(subject, subjectPublicKey, issuer, issuerPrivateKey, issuerPublicKey,
            ca, serial, NOT_BEFORE, NOT_AFTER);
    }

    private static X509Certificate generateCertificate(X500Name subject, PublicKey subjectPublicKey,
                                                       X500Name issuer, PrivateKey issuerPrivateKey, PublicKey issuerPublicKey,
                                                       boolean ca, BigInteger serial,
                                                       Date notBefore, Date notAfter) throws Exception {
        final JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, subjectPublicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(subjectPublicKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(issuerPublicKey));
        if (ca) {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static X509CRL generateCrl(X500Name issuer, PrivateKey issuerPrivateKey,
                                       BigInteger... revokedCertificateSerials) throws Exception {
        final X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, NOT_BEFORE);
        builder.setNextUpdate(NOT_AFTER);
        for (final BigInteger serial : revokedCertificateSerials) {
            builder.addCRLEntry(serial, NOT_BEFORE, 0);
        }
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        return new JcaX509CRLConverter().getCRL(builder.build(signer));
    }

    private static CertStore buildCrlStore(X509CRL... crls) throws Exception {
        return CertStore.getInstance("Collection", new CollectionCertStoreParameters(List.of(crls)));
    }

    private static CertStore buildCertificateAndCrlStore(List<X509Certificate> certificates, List<X509CRL> crls) throws Exception {
        final List<Object> storeContents = new ArrayList<>(certificates);
        storeContents.addAll(crls);
        return CertStore.getInstance("Collection", new CollectionCertStoreParameters(storeContents));
    }
}
