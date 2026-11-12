// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.exceptions;

import java.net.URI;

/**
 * Thrown when the OCSP responder returns the unknown status for the user certificate.
 */
public class UserCertificateUnknownStatusException extends UserCertificateOCSPCheckFailedException {

    public UserCertificateUnknownStatusException(URI ocspResponderUri) {
        super("Unknown status", ocspResponderUri);
    }
}
