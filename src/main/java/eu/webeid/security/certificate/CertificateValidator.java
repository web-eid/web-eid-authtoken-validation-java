// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotTrustedException;
import eu.webeid.security.exceptions.CertificateNotYetValidException;
import eu.webeid.security.exceptions.CertificateRevocationCheckFailedException;
import eu.webeid.security.exceptions.CertificateRevokedException;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.validator.revocationcheck.CertificateRevocationChecker;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationMode;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

public final class CertificateValidator {

    private static final String JDK_OCSP_NONCE_PROPERTY = "jdk.security.certpath.ocspNonce";

    public static void requireCertificateIsValidOnDate(X509Certificate cert, Date date, String subject) throws CertificateNotYetValidException, CertificateExpiredException {
        try {
            cert.checkValidity(date);
        } catch (java.security.cert.CertificateNotYetValidException e) {
            throw new CertificateNotYetValidException(subject, e);
        } catch (java.security.cert.CertificateExpiredException e) {
            throw new CertificateExpiredException(subject, e);
        }
    }

    /**
     * Validates that the provided {@code certificate} is trusted and performs certificate revocation checking
     * depending on {@code revocationMode}.
     * <p>
     * Trust validation is performed by building a certification path from {@code certificate} to one of the
     * configured {@code trustedCACertificateAnchors} using the supplied {@code trustedCACertificateCertStore}.
     * The effective validation time is {@code now}. In addition, the trust anchor certificate's validity period
     * is explicitly validated.
     * It is assumed that each configured trust anchor represents the intermediate certificate authority that directly
     * issued the subject certificate.
     * <p>
     * Revocation behavior is controlled by {@code revocationMode}:
     * <ul>
     *   <li>{@link RevocationMode#DISABLED} - no revocation checking is performed. Both
     *       {@code certificateRevocationChecker} and {@code customPkixRevocationChecker} must be {@code null}.</li>
     *   <li>{@link RevocationMode#CUSTOM_CHECKER} - revocation is checked by the provided
     *       {@code certificateRevocationChecker}. Platform (provider default) revocation checking is disabled.
     *       {@code customPkixRevocationChecker} must be {@code null}.</li>
     *   <li>{@link RevocationMode#CUSTOM_PKIX} - revocation is checked by the provided
     *       {@code customPkixRevocationChecker} installed as the (only) PKIX cert path checker during a separate
     *       validation pass. Provider default revocation checking is disabled.
     *       {@code certificateRevocationChecker} must be {@code null}.</li>
     *   <li>{@link RevocationMode#PLATFORM_OCSP} - revocation is checked using the platform PKIX revocation checker
     *       configured to enforce OCSP checking for the subject certificate with no fallback to CRLs
     *       ({@link PKIXRevocationChecker.Option#ONLY_END_ENTITY} and {@link PKIXRevocationChecker.Option#NO_FALLBACK}).
     *       When {@code platformOcspNonceEnabled} is true, a fresh OCSP nonce is included in each request.
     *       An explicitly set {@code jdk.security.certpath.ocspNonce} JVM property takes precedence over this setting
     *       and leaves nonce handling to the JDK. The JDK provider remains responsible for
     *       response nonce validation and may accept a response without one.
     *       Provider default revocation checking is disabled. Both custom checker parameters must be {@code null}.</li>
     * </ul>
     *
     * @param certificate                   the subject certificate to validate
     * @param trustedCACertificateAnchors   trust anchors used for PKIX path building (Web eID typically configures issuing intermediates)
     * @param trustedCACertificateCertStore certificate store containing trusted CA/intermediate certificates used during path building
     * @param now                           validation time used for certificate validity and PKIX path building
     * @param revocationMode                revocation checking mode
     * @param certificateRevocationChecker  custom certificate revocation checker (required only for {@code CUSTOM_CHECKER})
     * @param customPkixRevocationChecker   custom PKIX revocation checker (required only for {@code CUSTOM_PKIX})
     * @param platformOcspNonceEnabled      whether to supply a fresh OCSP nonce when the JVM nonce property is unset;
     *                                     ignored in other revocation modes
     * @return a list of {@link RevocationInfo} objects; the list is non-null and may be empty.
     * It is populated for {@link RevocationMode#CUSTOM_CHECKER}, and may be populated for
     * {@link RevocationMode#CUSTOM_PKIX} when the provided {@code customPkixRevocationChecker}
     * has an explicit OCSP responder URI configured; otherwise it is empty.
     * <p>
     * @throws NullPointerException            if any required parameter is {@code null}
     * @throws IllegalArgumentException        if the supplied checker parameters are inconsistent with {@code revocationMode}
     * @throws CertificateNotYetValidException if the subject or trust anchor certificate is not yet valid at {@code now}
     * @throws CertificateExpiredException     if the subject or trust anchor certificate is expired at {@code now}
     * @throws CertificateNotTrustedException  if no valid certification path can be built to the configured trust anchors
     * @throws CertificateRevokedException     if a PKIX revocation checker reports that the subject certificate is revoked
     * @throws CertificateRevocationCheckFailedException if a PKIX revocation checker cannot determine the revocation status
     * @throws JceException                    if the underlying JCA/JCE implementation fails unexpectedly
     * @throws AuthTokenException              if a custom revocation checker fails or reports the certificate as revoked
     */
    public static List<RevocationInfo> validateCertificateTrustAndRevocation(X509Certificate certificate,
                                                                             Set<TrustAnchor> trustedCACertificateAnchors,
                                                                             CertStore trustedCACertificateCertStore,
                                                                             Date now,
                                                                             RevocationMode revocationMode,
                                                                             CertificateRevocationChecker certificateRevocationChecker,
                                                                             PKIXRevocationChecker customPkixRevocationChecker,
                                                                             boolean platformOcspNonceEnabled) throws AuthTokenException {

        requireNonNull(certificate, "certificate");
        requireNonNull(trustedCACertificateAnchors, "trustedCACertificateAnchors");
        requireNonNull(trustedCACertificateCertStore, "trustedCACertificateCertStore");
        requireNonNull(now, "now");
        requireNonNull(revocationMode, "revocationMode");

        requireCertificateIsValidOnDate(certificate, now, "User");

        final X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(certificate);

        try {
            final PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustedCACertificateAnchors, selector);
            pkixBuilderParameters.setDate(now);
            pkixBuilderParameters.addCertStore(trustedCACertificateCertStore);

            List<RevocationInfo> revocationInfoList = List.of();
            PKIXRevocationChecker pkixRevocationChecker = null;

            switch (revocationMode) {
                case DISABLED -> {
                    if (customPkixRevocationChecker != null || certificateRevocationChecker != null) {
                        throw new IllegalArgumentException("customPkixRevocationChecker and certificateRevocationChecker must be null when revocationMode is DISABLED");
                    }
                }

                case CUSTOM_CHECKER -> {
                    if (customPkixRevocationChecker != null) {
                        throw new IllegalArgumentException("customPkixRevocationChecker must be null when revocationMode is CUSTOM_CHECKER");
                    }
                    if (certificateRevocationChecker == null) {
                        throw new IllegalArgumentException("certificateRevocationChecker must be provided when revocationMode is CUSTOM_CHECKER");
                    }
                }

                case CUSTOM_PKIX -> {
                    if (certificateRevocationChecker != null) {
                        throw new IllegalArgumentException("certificateRevocationChecker must be null when revocationMode is CUSTOM_PKIX");
                    }
                    if (customPkixRevocationChecker == null) {
                        throw new IllegalArgumentException("customPkixRevocationChecker must be provided when revocationMode is CUSTOM_PKIX");
                    }
                    pkixRevocationChecker = customPkixRevocationChecker;

                    if (customPkixRevocationChecker.getOcspResponder() != null) {
                        revocationInfoList = List.of(new RevocationInfo(customPkixRevocationChecker.getOcspResponder(), null));
                    }
                }

                case PLATFORM_OCSP -> {
                    if (customPkixRevocationChecker != null || certificateRevocationChecker != null) {
                        throw new IllegalArgumentException("customPkixRevocationChecker and certificateRevocationChecker must be null when revocationMode is PLATFORM_OCSP");
                    }

                    pkixRevocationChecker = buildOcspEnforcedPkixRevocationChecker(platformOcspNonceEnabled);
                }

                default -> throw new IllegalStateException("Unhandled revocationMode: " + revocationMode);
            }

            // Build the trusted path without revocation checking. Revocation is validated separately below so that
            // CertPathValidatorException and its structured reason are not hidden by CertPathBuilderException.
            pkixBuilderParameters.setRevocationEnabled(false);
            // See the comment in buildCertStoreFromCertificates() below why we use the default JCE provider.
            final CertPathBuilder certPathBuilder = CertPathBuilder.getInstance(CertPathBuilder.getDefaultType());
            final PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) certPathBuilder.build(pkixBuilderParameters);

            final X509Certificate trustedCACert = result.getTrustAnchor().getTrustedCert();
            if (trustedCACert == null) {
                throw new IllegalStateException("TrustAnchor.getTrustedCert() returned null, it must contain a trusted certificate");
            }

            // PKIX path building does not validate trust anchor validity period, do it ourselves.
            requireCertificateIsValidOnDate(trustedCACert, now, "Trusted CA");

            if (pkixRevocationChecker != null) {
                validateRevocation(
                        result,
                        pkixBuilderParameters,
                        pkixRevocationChecker,
                        certificate
                );
            } else if (revocationMode == RevocationMode.CUSTOM_CHECKER) {
                if (!certificate.getIssuerX500Principal().equals(trustedCACert.getSubjectX500Principal())) {
                    throw new IllegalStateException(
                            "Trust anchor is not the issuer of the subject certificate, check your configured certificate authorities. " +
                                    "Subject issuer=" + certificate.getIssuerX500Principal() +
                                    ", trust anchor subject=" + trustedCACert.getSubjectX500Principal()
                    );
                }
                revocationInfoList = certificateRevocationChecker.validateCertificateNotRevoked(certificate, trustedCACert);
            }

            return revocationInfoList;

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new JceException(e);
        } catch (CertPathBuilderException e) {
            throw new CertificateNotTrustedException(certificate, e);
        }
    }

    public static Set<TrustAnchor> buildTrustAnchorsFromCertificates(Collection<X509Certificate> certificates) {
        return certificates.stream()
            .map(cert -> new TrustAnchor(cert, null)).collect(Collectors.toUnmodifiableSet());
    }

    private static void validateRevocation(PKIXCertPathBuilderResult pathBuilderResult,
                                           PKIXBuilderParameters pkixBuilderParameters,
                                           PKIXRevocationChecker revocationChecker,
                                           X509Certificate certificate)
            throws AuthTokenException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        // Reuse the parameters, restrict validation to the trust anchor selected during path building.
        pkixBuilderParameters.setTrustAnchors(Set.of(pathBuilderResult.getTrustAnchor()));
        // Provider-default revocation remains disabled; adding an explicit checker is sufficient for it to run.
        pkixBuilderParameters.setCertPathCheckers(List.of(revocationChecker));

        final CertPathValidator certPathValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
        try {
            certPathValidator.validate(pathBuilderResult.getCertPath(), pkixBuilderParameters);
        } catch (CertPathValidatorException e) {
            if (e.getReason() == CertPathValidatorException.BasicReason.REVOKED) {
                throw new CertificateRevokedException(certificate, e);
            }
            if (e.getReason() == CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS ||
                    e.getReason() == CertPathValidatorException.BasicReason.UNSPECIFIED) {
                throw new CertificateRevocationCheckFailedException(certificate, e);
            }
            throw new CertificateNotTrustedException(certificate, e);
        }
    }

    public static CertStore buildCertStoreFromCertificates(Collection<X509Certificate> certificates) throws JceException {
        // Use the default JCE provider as there is no reason to use Bouncy Castle, moreover BC requires
        // the validated certificate to be in the certificate store which breaks the clean immutable usage of
        // trustedCACertificateCertStore in SubjectCertificateTrustedValidator.
        try {
            return CertStore.getInstance("Collection", new CollectionCertStoreParameters(certificates));
        } catch (GeneralSecurityException e) {
            throw new JceException(e);
        }
    }

    /**
     * Builds a PKIXRevocationChecker that enforces subject certificate checking with OCSP:
     * - ONLY_END_ENTITY: check only the leaf subject certificate with OCSP
     * - NO_FALLBACK: do not fall back to CRLs if OCSP fails
     */
    private static PKIXRevocationChecker buildOcspEnforcedPkixRevocationChecker(boolean platformOcspNonceEnabled) throws NoSuchAlgorithmException {
        final CertPathValidator certPathValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
        final PKIXRevocationChecker checker = (PKIXRevocationChecker) certPathValidator.getRevocationChecker();
        checker.setOptions(EnumSet.of(
                PKIXRevocationChecker.Option.ONLY_END_ENTITY,
                PKIXRevocationChecker.Option.NO_FALLBACK
        ));
        configureOcspNonce(checker, platformOcspNonceEnabled, System.getProperty(JDK_OCSP_NONCE_PROPERTY));
        return checker;
    }

    static void configureOcspNonce(PKIXRevocationChecker checker, boolean platformOcspNonceEnabled, String jdkOcspNonceProperty) {
        // Only supply our nonce when enabled and the JVM property is unset; explicit values take precedence.
        if (platformOcspNonceEnabled && jdkOcspNonceProperty == null) {
            checker.setOcspExtensions(List.of(OcspNonceExtension.create()));
        }
    }

    private CertificateValidator() {
        throw new IllegalStateException("Utility class");
    }

}
