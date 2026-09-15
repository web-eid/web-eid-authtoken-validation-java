// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when user certificate revocation check with OCSP fails.
 */
public class UserCertificateOCSPCheckFailedException extends AuthTokenException {
    public UserCertificateOCSPCheckFailedException(Throwable cause) {
        super("User certificate revocation check has failed", cause);
    }

    public UserCertificateOCSPCheckFailedException(String message) {
        super("User certificate revocation check has failed: " + message);
    }
}
