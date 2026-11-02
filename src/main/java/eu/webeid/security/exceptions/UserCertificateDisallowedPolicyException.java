// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when the user certificate does not satisfy the configured allowed or disallowed policy restrictions.
 */
public class UserCertificateDisallowedPolicyException extends AuthTokenException {
    public UserCertificateDisallowedPolicyException() {
        super("Disallowed user certificate policy");
    }
}
