// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
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
