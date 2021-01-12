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
import org.webeid.security.exceptions.UserCertificateNotTrustedException;
import org.webeid.security.validator.AuthTokenValidatorData;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Collection;

public final class SubjectCertificateTrustedValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectCertificateTrustedValidator.class);

    private final Collection<X509Certificate> trustedCACertificates;
    private X509Certificate trustedCACertificate;

    public SubjectCertificateTrustedValidator(Collection<X509Certificate> trustedCACertificates) {
        this.trustedCACertificates = trustedCACertificates;
    }

    /**
     * Validates that the user certificate from the authentication token is signed by a trusted certificate authority.
     *
     * @param actualTokenData authentication token data that contains the user certificate.
     * @throws UserCertificateNotTrustedException when user certificate is not signed by a trusted CA or is valid after CA certificate.
     */
    public void validateCertificateTrusted(AuthTokenValidatorData actualTokenData) throws UserCertificateNotTrustedException {

        final X509Certificate certificate = actualTokenData.getSubjectCertificate();

        for (final X509Certificate caCertificate : trustedCACertificates) {
            try {
                certificate.verify(caCertificate.getPublicKey());
                if (certificate.getNotAfter().after(caCertificate.getNotAfter())) {
                    throw new UserCertificateNotTrustedException("Trusted CA certificate expires earlier than the user certificate");
                }
                this.trustedCACertificate = caCertificate;
                LOG.debug("User certificate is signed with a trusted CA certificate");
                return;
            } catch (GeneralSecurityException e) {
                LOG.trace("Error verifying signer's certificate {} against CA certificate {}", certificate.getSubjectDN(), caCertificate.getSubjectDN());
            }
        }
        throw new UserCertificateNotTrustedException();
    }

    public X509Certificate getSubjectCertificateIssuerCertificate() {
        return trustedCACertificate;
    }
}
