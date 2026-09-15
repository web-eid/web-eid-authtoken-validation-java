// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when the user certificate purpose is not client authentication.
 */
public class UserCertificateWrongPurposeException extends AuthTokenException {
    public UserCertificateWrongPurposeException() {
        super("User certificate is not meant to be used as an authentication certificate");
    }
}
