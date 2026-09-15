// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when user certificate parsing fails.
 */
public class UserCertificateParseException extends AuthTokenException {
    public UserCertificateParseException(Throwable cause) {
        super("Error parsing certificate", cause);
    }
}
