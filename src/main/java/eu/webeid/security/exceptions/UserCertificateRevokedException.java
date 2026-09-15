// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when the user certificate has been revoked.
 */
public class UserCertificateRevokedException extends AuthTokenException {
    public UserCertificateRevokedException() {
        super("User certificate has been revoked");
    }

    public UserCertificateRevokedException(String msg) {
        super("User certificate has been revoked: " + msg);
    }
}
