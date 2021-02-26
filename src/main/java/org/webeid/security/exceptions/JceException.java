package org.webeid.security.exceptions;

import java.security.GeneralSecurityException;

public class JceException extends TokenValidationException {
    public JceException(GeneralSecurityException e) {
        super("Java Cryptography Extension loading or configuration failed", e);
    }
}
