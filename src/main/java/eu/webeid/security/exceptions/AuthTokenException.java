// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

/**
 * Base class for all authentication token validation exceptions.
 */
public abstract class AuthTokenException extends Exception {

    protected AuthTokenException(String msg) {
        super(msg);
    }

    protected AuthTokenException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
