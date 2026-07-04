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
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.CertificateNotTrustedException;
import eu.webeid.security.exceptions.OCSPCertificateException;
import eu.webeid.security.exceptions.UserCertificateOCSPCheckFailedException;
import eu.webeid.security.validator.ocsp.OcspResponseValidator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.net.URI;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static eu.webeid.security.validator.ocsp.OcspUrl.getOcspUri;

/**
 * An OCSP service that uses the responders from the Certificates' Authority Information Access (AIA) extension.
 */
public class AiaOcspService implements OcspService {

    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    private final Set<TrustAnchor> trustedCACertificateAnchors;
    private final CertStore trustedCACertificateCertStore;
    private final X509Certificate certificateIssuerCertificate;
    private final List<X509Certificate> additionalIntermediateCertificates;
    private final URI url;
    private final boolean supportsNonce;
    private final AiaOcspServiceConfiguration.ResponderIssuerMatchingPolicy responderIssuerMatchingPolicy;

    /**
     * Creates an AIA OCSP service for a single validation run of the given certificate.
     *
     * @param configuration AIA OCSP service configuration
     * @param certificate the certificate whose revocation status the service answers for
     * @param certificateIssuerCertificate the certificate that directly issued the given certificate; the OCSP
     *     responder must be authorized by it
     * @param additionalIntermediateCertificates untrusted, token-supplied intermediate certificates that may be
     *     needed to build the responder's certification path to a trusted CA; may be empty
     */
    public AiaOcspService(AiaOcspServiceConfiguration configuration,
                          X509Certificate certificate,
                          X509Certificate certificateIssuerCertificate,
                          List<X509Certificate> additionalIntermediateCertificates) throws AuthTokenException {
        Objects.requireNonNull(configuration);
        this.trustedCACertificateAnchors = configuration.getTrustedCACertificateAnchors();
        this.trustedCACertificateCertStore = configuration.getTrustedCACertificateCertStore();
        this.certificateIssuerCertificate = Objects.requireNonNull(certificateIssuerCertificate);
        this.additionalIntermediateCertificates = Objects.requireNonNull(additionalIntermediateCertificates);
        this.url = getOcspAiaUrlFromCertificate(Objects.requireNonNull(certificate));
        this.supportsNonce = !configuration.getNonceDisabledOcspUrls().contains(this.url);
        this.responderIssuerMatchingPolicy = configuration.getResponderIssuerMatchingPolicy();
    }

    @Override
    public boolean doesSupportNonce() {
        return supportsNonce;
    }

    @Override
    public URI getAccessLocation() {
        return url;
    }

    @Override
    public void validateResponderCertificate(X509CertificateHolder cert, Date now) throws AuthTokenException {
        try {
            final X509Certificate certificate = certificateConverter.getCertificate(cert);
            // The responder certificate's validity on the current date is checked as part of the certification
            // path validation. A responder may be issued by a token-supplied intermediate that is not itself
            // trusted, so the intermediates are offered as path candidates; the path must still terminate at a
            // trusted anchor. The responder certificate itself is never revocation-checked, whatever revocation
            // policy the CA has chosen for it under RFC 6960 section 4.2.2.2.1: OCSP-checking a responder against
            // its own service would be circular, and no CRL-based check of the responder certificate is implemented
            // (the only CRL use in the library is the default JDK checker's CRL fallback in
            // CertificateValidator.validateIntermediateCertificatesNotRevoked). In practice all production Estonian,
            // Belgian and Finnish AIA responder certificates carry id-pkix-ocsp-nocheck, which tells clients to skip
            // the check anyway.
            //
            // With exact issuer matching, the intermediate CA certificates are not checked again: this validation
            // run has already vetted the exact issuer while validating the subject certificate, as either a
            // configured trust anchor or a token-supplied intermediate that was revocation-checked then. With
            // subject-and-public-key matching, however, the responder path may use a different equivalent
            // cross-certificate, so every non-anchor intermediate in that path is revocation-checked.
            final X509Certificate responderIssuerCertificate = CertificateValidator.validateIsSignedByTrustedCA(
                certificate,
                "AIA OCSP responder",
                trustedCACertificateAnchors,
                trustedCACertificateCertStore,
                additionalIntermediateCertificates,
                getIntermediateRevocationCheckByPolicy(),
                now
            );
            // RFC 6960 section 4.2.2.2: the response must be signed by the CA that issued the subject certificate
            // or by a responder directly delegated by it; a locally configured responder is handled by
            // DesignatedOcspService.
            if (matchesCertificateIssuer(certificate, certificateIssuerCertificate)) {
                // The response is signed by the issuing CA itself; the OCSP-signing extended key usage is required
                // only for delegated responder certificates.
                return;
            }
            if (representsSameCA(certificate, certificateIssuerCertificate)) {
                // The response is signed directly by the issuing CA, but with a certificate that is only equivalent
                // to (same subject and public key), not identical with, the subject certificate's issuer certificate.
                // This can only happen under the EXACT_CERTIFICATE policy. Report it explicitly, because otherwise
                // control falls through to the delegated-responder branch below and fails with a misleading
                // missing-OCSP-signing-extended-key-usage error; the SUBJECT_AND_PUBLIC_KEY policy accepts it.
                throw new CertificateNotTrustedException(certificate,
                    new CertificateException("OCSP response is signed by a certificate equivalent to but not the "
                        + "same as the subject certificate issuer; the exact-certificate responder issuer matching "
                        + "policy requires the issuer certificate itself"));
            }
            OcspResponseValidator.validateHasSigningExtension(certificate);
            if (!matchesCertificateIssuer(responderIssuerCertificate, certificateIssuerCertificate)) {
                throw new CertificateNotTrustedException(certificate,
                    new CertificateException("OCSP responder is not authorized by the subject certificate issuer"));
            }
        } catch (CertificateException e) {
            throw new OCSPCertificateException("Invalid responder certificate", e);
        }
    }

    private static boolean representsSameCA(X509Certificate first, X509Certificate second) {
        return first.getSubjectX500Principal().equals(second.getSubjectX500Principal())
            && Arrays.equals(first.getPublicKey().getEncoded(), second.getPublicKey().getEncoded());
    }

    private boolean matchesCertificateIssuer(X509Certificate first, X509Certificate second) {
        return switch (responderIssuerMatchingPolicy) {
            case EXACT_CERTIFICATE -> first.equals(second);
            case SUBJECT_AND_PUBLIC_KEY -> representsSameCA(first, second);
        };
    }

    private CertificateValidator.IntermediateRevocationCheck getIntermediateRevocationCheckByPolicy() {
        return switch (responderIssuerMatchingPolicy) {
            case EXACT_CERTIFICATE -> CertificateValidator.IntermediateRevocationCheck.DISABLED;
            case SUBJECT_AND_PUBLIC_KEY -> CertificateValidator.IntermediateRevocationCheck.ENABLED;
        };
    }

    private static URI getOcspAiaUrlFromCertificate(X509Certificate certificate) throws AuthTokenException {
        return getOcspUri(certificate).orElseThrow(() ->
            new UserCertificateOCSPCheckFailedException("Getting the AIA OCSP responder field from the certificate failed")
        );
    }

}
