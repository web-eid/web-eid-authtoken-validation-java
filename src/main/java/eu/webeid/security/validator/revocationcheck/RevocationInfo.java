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
package eu.webeid.security.validator.revocationcheck;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public record RevocationInfo(URI ocspResponderUri, Map<String, Object> ocspResponseAttributes) {

    public static final String KEY_OCSP_REQUEST = "OCSP_REQUEST";
    public static final String KEY_OCSP_RESPONSE = "OCSP_RESPONSE";
    public static final String KEY_OCSP_ERROR = "OCSP_ERROR";
    public static final String KEY_HTTP_STATUS_CODE = "HTTP_STATUS_CODE";
    public static final String KEY_REQUEST_DURATION = "REQUEST_DURATION";
    public static final String KEY_CIRCUIT_BREAKER_STATISTICS = "CIRCUIT_BREAKER_STATISTICS";
    public static final String KEY_OCSP_RESPONSE_TIME = "OCSP_RESPONSE_TIME";

    public RevocationInfo(URI ocspResponderUri, Map<String, Object> ocspResponseAttributes) {
        this.ocspResponderUri = ocspResponderUri;
        this.ocspResponseAttributes = ocspResponseAttributes != null
            ? Map.copyOf(ocspResponseAttributes)
            : null;
    }

    public RevocationInfo withAdditionalOcspResponseAttribute(String key, Object value) {
        if (value == null) {
            return this;
        }
        Map<String, Object> newOcspResponseAttributes = ocspResponseAttributes != null
            ? new HashMap<>(ocspResponseAttributes)
            : new HashMap<>();
        newOcspResponseAttributes.put(key, value);
        return new RevocationInfo(ocspResponderUri, newOcspResponseAttributes);
    }
}
