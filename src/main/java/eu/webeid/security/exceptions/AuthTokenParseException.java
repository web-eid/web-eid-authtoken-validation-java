// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Thrown when authentication token parsing fails.
 */
public class AuthTokenParseException extends AuthTokenException {

    public AuthTokenParseException(String message) {
        super(message);
    }

    public AuthTokenParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
