// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.exceptions;

import eu.webeid.security.exceptions.AuthTokenException;

public class UserCertificateOCSPException extends AuthTokenException {

    public UserCertificateOCSPException(String message) {
        super(message);
    }

    public UserCertificateOCSPException(String message, Throwable exception) {
        super(message, exception);
    }

}
