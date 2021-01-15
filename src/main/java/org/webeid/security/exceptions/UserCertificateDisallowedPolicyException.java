package org.webeid.security.exceptions;

/**
 * Thrown when any of the configured disallowed policies is present in the user certificate.
 */
public class UserCertificateDisallowedPolicyException extends TokenValidationException {
    public UserCertificateDisallowedPolicyException() {
        super("Disallowed user certificate policy");
    }
}
