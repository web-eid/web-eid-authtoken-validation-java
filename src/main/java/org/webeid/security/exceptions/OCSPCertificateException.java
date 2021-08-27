package org.webeid.security.exceptions;

public class OCSPCertificateException extends TokenValidationException {

    public OCSPCertificateException(String message) {
        super(message);
    }

    public OCSPCertificateException(String message, Throwable exception) {
        super(message, exception);
    }

}
