// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

import java.security.cert.X509Certificate;

/**
 * Thrown when the given certificate has been revoked.
 */
public class CertificateRevokedException extends AuthTokenException {

    public CertificateRevokedException(X509Certificate certificate, Throwable cause) {
        super("Certificate " + certificate.getSubjectX500Principal() + " has been revoked", cause);
    }

    protected CertificateRevokedException(String message) {
        super(message);
    }
}
