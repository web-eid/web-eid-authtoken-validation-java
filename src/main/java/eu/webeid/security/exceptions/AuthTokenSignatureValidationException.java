// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when authentication token signature validation fails.
 */
public class AuthTokenSignatureValidationException extends AuthTokenException {

    public AuthTokenSignatureValidationException() {
        super("Token signature validation has failed. Check that the origin and nonce are correct.");
    }

}
