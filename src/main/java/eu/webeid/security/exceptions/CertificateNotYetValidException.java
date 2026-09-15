// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when the certificate's valid from date is in the future.
 */
public class CertificateNotYetValidException extends AuthTokenException {
    public CertificateNotYetValidException(String subject, Throwable cause) {
        super(subject + " certificate is not yet valid", cause);
    }
}
