// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.exceptions;

import eu.webeid.security.exceptions.AuthTokenException;

public class OCSPCertificateException extends AuthTokenException {

    public OCSPCertificateException(String message) {
        super(message);
    }

    public OCSPCertificateException(String message, Throwable exception) {
        super(message, exception);
    }

}
