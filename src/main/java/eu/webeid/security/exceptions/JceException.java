// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

import java.security.GeneralSecurityException;

public class JceException extends AuthTokenException {
    public JceException(GeneralSecurityException e) {
        super("Java Cryptography Extension loading or configuration failed", e);
    }
}
