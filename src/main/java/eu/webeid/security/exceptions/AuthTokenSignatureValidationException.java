// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when authentication token signature validation fails.
 */
public class AuthTokenSignatureValidationException extends AuthTokenException {

    private static final String MESSAGE = "Token signature validation has failed. Check that the origin and nonce are correct.";

    public AuthTokenSignatureValidationException() {
        super(MESSAGE);
    }

    public AuthTokenSignatureValidationException(Throwable cause) {
        super(MESSAGE, cause);
    }

}
