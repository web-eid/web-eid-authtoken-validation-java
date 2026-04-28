/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
