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

import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotYetValidException;
import eu.webeid.security.exceptions.JceException;
import eu.webeid.security.exceptions.CertificateNotTrustedException;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
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

    public static void certificateIsValidOnDate(X509Certificate cert, Date date, String subject) throws CertificateNotYetValidException, CertificateExpiredException {
        try {
            cert.checkValidity(date);
        } catch (java.security.cert.CertificateNotYetValidException e) {
            throw new CertificateNotYetValidException(subject, e);
        } catch (java.security.cert.CertificateExpiredException e) {
            throw new CertificateExpiredException(subject, e);
        }
    }

    public static void trustedCACertificatesAreValidOnDate(Set<TrustAnchor> trustedCACertificateAnchors, Date date) throws CertificateNotYetValidException, CertificateExpiredException {
        for (TrustAnchor cert : trustedCACertificateAnchors) {
            certificateIsValidOnDate(cert.getTrustedCert(), date, "Trusted CA");
        }
    }

    public static X509Certificate validateIsSignedByTrustedCA(X509Certificate certificate,
                                                              Set<TrustAnchor> trustedCACertificateAnchors,
                                                              CertStore trustedCACertificateCertStore,
                                                              Date date) throws CertificateNotTrustedException, JceException {
        final X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(certificate);

        try {
            final PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustedCACertificateAnchors, selector);
            pkixBuilderParameters.setRevocationEnabled(false);
            pkixBuilderParameters.setDate(date);
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
        return Collections.unmodifiableSet(certificates.stream()
            .map(cert -> new TrustAnchor(cert, null))
            .collect(Collectors.toSet()));
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

    private CertificateValidator() {
        throw new IllegalStateException("Utility class");
    }

}
