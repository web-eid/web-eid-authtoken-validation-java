// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.exceptions;

import eu.webeid.security.exceptions.CertificateRevocationCheckFailedException;

public class OCSPCertificateException extends CertificateRevocationCheckFailedException {

    public OCSPCertificateException(String message) {
        super(message);
    }

    public OCSPCertificateException(String message, Throwable exception) {
        super(message, exception);
    }

}
