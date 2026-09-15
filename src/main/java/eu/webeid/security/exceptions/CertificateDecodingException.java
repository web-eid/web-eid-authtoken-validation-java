// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.exceptions;

public class CertificateDecodingException extends AuthTokenException {
    public CertificateDecodingException(Throwable cause) {
        super("Certificate decoding from Base64 or parsing failed", cause);
    }
}
