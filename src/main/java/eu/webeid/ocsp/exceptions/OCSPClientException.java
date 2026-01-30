// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.exceptions;

public class OCSPClientException extends Exception {

    private final byte[] responseBody;

    private final Integer statusCode;

    public OCSPClientException() {
        this(null, null);
    }

    public OCSPClientException(String message) {
        this(message, null, null);
    }

    public OCSPClientException(Throwable cause) {
        this(null, cause, null, null);
    }

    public OCSPClientException(String message, Throwable cause) {
        this(message, cause, null, null);
    }

    public OCSPClientException(String message, byte[] responseBody, Integer statusCode) {
        this(message, null, responseBody, statusCode);
    }

    public OCSPClientException(String message, Throwable cause, byte[] responseBody, Integer statusCode) {
        super(message, cause);
        this.responseBody = responseBody;
        this.statusCode = statusCode;
    }

    public byte[] getResponseBody() {
        return responseBody;
    }

    public Integer getStatusCode() {
        return statusCode;
    }
}
