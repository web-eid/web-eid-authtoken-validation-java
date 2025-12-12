// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.exceptions;

import java.net.URI;

/**
 * Helper class for adding OCSP responder URL to messages.
 */
final class OcspResponderUriMessageAppender {

    static String appendResponderUri(String message, URI ocspResponderUri) {
        if (ocspResponderUri == null) {
            return message;
        }
        return message + " (OCSP responder: " + ocspResponderUri + ")";
    }

    private OcspResponderUriMessageAppender() {
        throw new IllegalStateException("Utility class");
    }
}
