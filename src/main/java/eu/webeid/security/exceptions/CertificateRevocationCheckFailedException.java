// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

import java.security.cert.X509Certificate;

/**
 * Thrown when the revocation status of the given certificate cannot be determined.
 */
public class CertificateRevocationCheckFailedException extends AuthTokenException {

    public CertificateRevocationCheckFailedException(X509Certificate certificate, Throwable cause) {
        super("Certificate revocation check failed for " + certificate.getSubjectX500Principal() +
                ": " + cause.getMessage(), cause);
    }

    protected CertificateRevocationCheckFailedException(String message) {
        super(message);
    }

    protected CertificateRevocationCheckFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
