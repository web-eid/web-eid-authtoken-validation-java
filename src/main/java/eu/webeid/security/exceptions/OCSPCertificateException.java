// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

public class OCSPCertificateException extends AuthTokenException {

    public OCSPCertificateException(String message) {
        super(message);
    }

    public OCSPCertificateException(String message, Throwable exception) {
        super(message, exception);
    }

}
