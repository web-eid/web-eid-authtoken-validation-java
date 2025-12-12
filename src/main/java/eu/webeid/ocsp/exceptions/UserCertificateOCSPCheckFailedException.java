// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.exceptions;

import eu.webeid.security.exceptions.CertificateRevocationCheckFailedException;

import java.net.URI;

import static eu.webeid.ocsp.exceptions.OcspResponderUriMessageAppender.appendResponderUri;

/**
 * Thrown when user certificate revocation check with OCSP fails.
 */
public class UserCertificateOCSPCheckFailedException extends CertificateRevocationCheckFailedException {

    public UserCertificateOCSPCheckFailedException(Throwable cause, URI ocspResponderUri) {
        super(appendResponderUri("User certificate revocation check has failed", ocspResponderUri), cause);
    }

    public UserCertificateOCSPCheckFailedException(String message, URI ocspResponderUri) {
        super(appendResponderUri("User certificate revocation check has failed: " + message, ocspResponderUri));
    }

    public UserCertificateOCSPCheckFailedException(String message) {
        super(message);
    }

}
