/*
 * Copyright (c) 2020 The Web eID Project
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

package org.webeid.security.validator.validators;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.webeid.security.exceptions.JceException;
import org.webeid.security.exceptions.UserCertificateNotTrustedException;
import org.webeid.security.validator.AuthTokenValidatorData;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.Set;

/**
 * Validator that validates that the user certificate from the authentication token is signed by a trusted certificate authority.
 * <p>
 * We use the default JCE provider as there is no reason to use Bouncy Castle, moreover BC requires the validated certificate
 * to be in the certificate store which breaks the clean immutable usage of {@code trustedRootCACertificateCertStore}.
 */
public final class SubjectCertificateTrustedValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificateTrustedValidator.class);

    private final Set<TrustAnchor> trustedRootCACertificateAnchors;
    private final CertStore trustedRootCACertificateCertStore;
    private X509Certificate subjectCertificateIssuerRootCertificate;

    public SubjectCertificateTrustedValidator(Set<TrustAnchor> trustedRootCACertificateAnchors, CertStore trustedRootCACertificateCertStore) {
        this.trustedRootCACertificateAnchors = trustedRootCACertificateAnchors;
        this.trustedRootCACertificateCertStore = trustedRootCACertificateCertStore;
    }

    /**
     * Validates that the user certificate from the authentication token is signed by a trusted certificate authority.
     *
     * @param actualTokenData authentication token data that contains the user certificate.
     * @throws UserCertificateNotTrustedException when user certificate is not signed by a trusted CA or is valid after CA certificate.
     */
    public void validateCertificateTrusted(AuthTokenValidatorData actualTokenData) throws UserCertificateNotTrustedException, JceException {

        final X509Certificate certificate = actualTokenData.getSubjectCertificate();

        final X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(certificate);

        try {
            final PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustedRootCACertificateAnchors, selector);
            pkixBuilderParameters.setRevocationEnabled(false);
            pkixBuilderParameters.addCertStore(trustedRootCACertificateCertStore);

            // See the comment in AuthTokenValidatorImpl constructor why we use the default JCE provider.
            final CertPathBuilder certPathBuilder = CertPathBuilder.getInstance(CertPathBuilder.getDefaultType());
            final PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) certPathBuilder.build(pkixBuilderParameters);

            subjectCertificateIssuerRootCertificate = result.getTrustAnchor().getTrustedCert();

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new JceException(e);
        } catch (CertPathBuilderException e) {
            LOG.trace("Error verifying signer's certificate {}: {}", certificate.getSubjectDN(), e);
            throw new UserCertificateNotTrustedException();
        }
    }

    public X509Certificate getSubjectCertificateIssuerRootCertificate() {
        return subjectCertificateIssuerRootCertificate;
    }
}
