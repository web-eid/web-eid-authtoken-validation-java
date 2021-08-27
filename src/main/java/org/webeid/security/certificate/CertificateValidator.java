package org.webeid.security.certificate;

import org.webeid.security.exceptions.CertificateNotTrustedException;
import org.webeid.security.exceptions.JceException;
import org.webeid.security.exceptions.UserCertificateExpiredException;
import org.webeid.security.exceptions.UserCertificateNotYetValidException;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

public final class CertificateValidator {

    /**
     * Checks whether the certificate was valid on the given date.
     */
    public static void certificateIsValidOnDate(X509Certificate cert, Date date) throws UserCertificateNotYetValidException, UserCertificateExpiredException {
        try {
            cert.checkValidity(date);
        } catch (CertificateNotYetValidException e) {
            throw new UserCertificateNotYetValidException(e);
        } catch (CertificateExpiredException e) {
            throw new UserCertificateExpiredException(e);
        }
    }

    public static X509Certificate validateIsSignedByTrustedCA(X509Certificate certificate,
                                                              Set<TrustAnchor> trustedCACertificateAnchors,
                                                              CertStore trustedCACertificateCertStore) throws CertificateNotTrustedException, JceException {
        final X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(certificate);

        try {
            final PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustedCACertificateAnchors, selector);
            pkixBuilderParameters.setRevocationEnabled(false);
            pkixBuilderParameters.addCertStore(trustedCACertificateCertStore);

            // See the comment in buildCertStoreFromCertificates() below why we use the default JCE provider.
            final CertPathBuilder certPathBuilder = CertPathBuilder.getInstance(CertPathBuilder.getDefaultType());
            final PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) certPathBuilder.build(pkixBuilderParameters);

            return result.getTrustAnchor().getTrustedCert();

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new JceException(e);
        } catch (CertPathBuilderException e) {
            throw new CertificateNotTrustedException(certificate, e);
        }
    }

    public static Set<TrustAnchor> buildTrustAnchorsFromCertificates(Collection<X509Certificate> certificates) {
        return certificates.stream()
            .map(cert -> new TrustAnchor(cert, null))
            .collect(Collectors.toSet());
    }

    public static Set<TrustAnchor> buildTrustAnchorsFromCertificate(X509Certificate certificate) {
        return buildTrustAnchorsFromCertificates(Collections.singleton(certificate));
    }

    public static CertStore buildCertStoreFromCertificates(Collection<X509Certificate> certificates) throws JceException {
        // We use the default JCE provider as there is no reason to use Bouncy Castle, moreover BC requires
        // the validated certificate to be in the certificate store which breaks the clean immutable usage of
        // trustedCACertificateCertStore in SubjectCertificateTrustedValidator.
        try {
            return CertStore.getInstance("Collection", new CollectionCertStoreParameters(certificates));
        } catch (GeneralSecurityException e) {
            throw new JceException(e);
        }
    }

    public static CertStore buildCertStoreFromCertificate(X509Certificate certificate) throws JceException {
        return buildCertStoreFromCertificates(Collections.singleton(certificate));
    }

    private CertificateValidator() {
        throw new IllegalStateException("Utility class");
    }

}
