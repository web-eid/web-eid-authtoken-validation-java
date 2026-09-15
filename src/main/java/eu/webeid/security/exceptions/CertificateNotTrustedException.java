// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

import java.security.cert.X509Certificate;

/**
 * Thrown when the given certificate is not signed by a trusted CA.
 */
public class CertificateNotTrustedException extends AuthTokenException {

    public CertificateNotTrustedException(X509Certificate certificate, Throwable e) {
        super("Certificate " + certificate.getSubjectX500Principal() + " is not trusted", e);
    }

}
