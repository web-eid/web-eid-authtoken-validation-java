package org.webeid.security.exceptions;

/**
 * Thrown when the user certificate policy is invalid.
 */
public class UserCertificateInvalidPolicyException extends TokenValidationException {
    public UserCertificateInvalidPolicyException() {
        super("User certificate policy is invalid");
    }
}
