// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when any of the configured disallowed policies is present in the user certificate.
 */
public class UserCertificateDisallowedPolicyException extends AuthTokenException {
    public UserCertificateDisallowedPolicyException() {
        super("Disallowed user certificate policy");
    }
}
