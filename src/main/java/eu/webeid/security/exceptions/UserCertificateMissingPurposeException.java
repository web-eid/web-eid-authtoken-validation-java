// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when the user certificate purpose field is missing or empty.
 */
public class UserCertificateMissingPurposeException extends AuthTokenException {
    public UserCertificateMissingPurposeException() {
        super("User certificate purpose is missing");
    }
}
