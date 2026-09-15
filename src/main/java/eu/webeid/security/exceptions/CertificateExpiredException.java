// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when the certificate's valid until date is in the past.
 */
public class CertificateExpiredException extends AuthTokenException {
    public CertificateExpiredException(String subject, Throwable cause) {
        super(subject + " certificate has expired", cause);
    }
}
