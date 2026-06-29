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

package eu.webeid.security.validator.ocsp.service;

import eu.webeid.security.certificate.CertificateValidator;
import eu.webeid.security.exceptions.CertificateNotTrustedException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
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
import java.security.PublicKey;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Verifies that an AIA OCSP responder certificate that only chains to a trusted root through a token-supplied
 * intermediate certificate (one that is not configured as a trusted CA) is validated correctly. This mirrors the
 * NFC-128 deployment where the root is trusted and the issuing intermediate is delivered in the authentication token's
 * {@code unverifiedIntermediateCertificates} field.
 */
class AiaOcspServiceTest {

    private static final Date NOW = new Date();
    private static final Date NOT_BEFORE = new Date(NOW.getTime() - 86_400_000L);
    private static final Date NOT_AFTER = new Date(NOW.getTime() + 86_400_000L);
    private static final String OCSP_URL = "http://ocsp.example/responder";

    private static X509Certificate intermediateCertificate;
    private static X509Certificate crossIntermediateCertificate;
    private static X509Certificate responderCertificate;
    private static X509Certificate siblingIntermediateCertificate;
    private static X509Certificate siblingResponderCertificate;
    private static AiaOcspService aiaOcspService;

    @BeforeAll
    static void setUp() throws Exception {
        final KeyPair rootKeyPair = generateKeyPair();
        final KeyPair intermediateKeyPair = generateKeyPair();
        final KeyPair responderKeyPair = generateKeyPair();
        final KeyPair siblingIntermediateKeyPair = generateKeyPair();
        final KeyPair siblingResponderKeyPair = generateKeyPair();
        final KeyPair subjectKeyPair = generateKeyPair();

        final X509Certificate rootCertificate = generateCertificate(
            "Test Root CA", rootKeyPair.getPublic(), "Test Root CA", rootKeyPair, 1, true, false, null);
        intermediateCertificate = generateCertificate(
            "Test Intermediate CA", intermediateKeyPair.getPublic(), "Test Root CA", rootKeyPair, 2, true, false, null);
        // An equivalent cross-certificate for the intermediate CA: same subject and public key as
        // intermediateCertificate, but a distinct certificate (different serial). RFC 6960 authorization must accept it.
        crossIntermediateCertificate = generateCertificate(
            "Test Intermediate CA", intermediateKeyPair.getPublic(), "Test Root CA", rootKeyPair, 7, true, false, null);
        // The OCSP responder is delegated by the intermediate CA (RFC 6960 CA-designated responder).
        responderCertificate = generateCertificate(
            "Test OCSP Responder", responderKeyPair.getPublic(), "Test Intermediate CA", intermediateKeyPair, 3, false, true, null);
        siblingIntermediateCertificate = generateCertificate(
            "Sibling Intermediate CA", siblingIntermediateKeyPair.getPublic(), "Test Root CA", rootKeyPair, 5, true, false, null);
        siblingResponderCertificate = generateCertificate(
            "Sibling OCSP Responder", siblingResponderKeyPair.getPublic(), "Sibling Intermediate CA",
            siblingIntermediateKeyPair, 6, false, true, null);
        // The subject certificate is only needed so that AiaOcspService can read the AIA OCSP URL from it.
        final X509Certificate subjectCertificate = generateCertificate(
            "Test Subject", subjectKeyPair.getPublic(), "Test Intermediate CA", intermediateKeyPair, 4, false, false, OCSP_URL);

        // Trust only the root. The intermediate that issued both the subject and the responder is NOT configured as
        // trusted, exactly like a deployment that relies on the token-supplied intermediate to build the chain.
        final Set<TrustAnchor> anchors = Collections.singleton(new TrustAnchor(rootCertificate, null));
        final CertStore emptyStore = CertificateValidator.buildCertStoreFromCertificates(Collections.emptyList());
        aiaOcspService = new AiaOcspService(
            new AiaOcspServiceConfiguration(Collections.emptySet(), anchors, emptyStore), subjectCertificate);
    }

    @Test
    void whenResponderChainsViaTokenIntermediate_thenValidationSucceeds() throws Exception {
        final X509CertificateHolder responderHolder = new X509CertificateHolder(responderCertificate.getEncoded());
        assertThatCode(() -> aiaOcspService.validateResponderCertificate(
            responderHolder, intermediateCertificate, Collections.singletonList(intermediateCertificate), NOW))
            .doesNotThrowAnyException();
    }

    @Test
    void whenResponderChainsViaTokenIntermediateButIntermediateMissing_thenValidationFails() throws Exception {
        final X509CertificateHolder responderHolder = new X509CertificateHolder(responderCertificate.getEncoded());
        // Without the token-supplied intermediate, the responder -> intermediate -> root path cannot be built.
        assertThatExceptionOfType(CertificateNotTrustedException.class)
            .isThrownBy(() -> aiaOcspService.validateResponderCertificate(
                responderHolder, intermediateCertificate, Collections.emptyList(), NOW));
    }

    @Test
    void whenResponderIssuerIsEquivalentCrossCertificate_thenValidationSucceeds() throws Exception {
        final X509CertificateHolder responderHolder = new X509CertificateHolder(responderCertificate.getEncoded());
        // The responder still chains to the root via the real intermediate, so its issuer in the built path is
        // intermediateCertificate. The subject issuer is passed as the equivalent cross-certificate (same subject and
        // public key, different certificate), which representsSameCA must treat as the same CA.
        assertThatCode(() -> aiaOcspService.validateResponderCertificate(
            responderHolder, crossIntermediateCertificate, Collections.singletonList(intermediateCertificate), NOW))
            .doesNotThrowAnyException();
    }

    @Test
    void whenResponderIsIssuedBySiblingIntermediate_thenValidationFails() throws Exception {
        final X509CertificateHolder responderHolder =
            new X509CertificateHolder(siblingResponderCertificate.getEncoded());

        assertThatExceptionOfType(CertificateNotTrustedException.class)
            .isThrownBy(() -> aiaOcspService.validateResponderCertificate(
                responderHolder, intermediateCertificate,
                List.of(intermediateCertificate, siblingIntermediateCertificate), NOW))
            .withCauseInstanceOf(CertificateException.class);
    }

    private static KeyPair generateKeyPair() throws Exception {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate generateCertificate(String subjectCn, PublicKey subjectPublicKey,
                                                       String issuerCn, KeyPair issuerKeyPair, long serial,
                                                       boolean ca, boolean ocspSigning, String ocspUrl) throws Exception {
        final JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            new X500Name("CN=" + issuerCn), BigInteger.valueOf(serial), NOT_BEFORE, NOT_AFTER,
            new X500Name("CN=" + subjectCn), subjectPublicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(subjectPublicKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(issuerKeyPair.getPublic()));
        if (ca) {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }
        if (ocspSigning) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        }
        if (ocspUrl != null) {
            builder.addExtension(Extension.authorityInfoAccess, false,
                new AuthorityInformationAccess(new AccessDescription(AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl))));
        }
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
