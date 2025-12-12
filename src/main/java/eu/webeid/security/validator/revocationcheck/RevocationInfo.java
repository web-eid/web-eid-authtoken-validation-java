// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
package eu.webeid.security.validator.revocationcheck;

import java.net.URI;
import java.util.Map;

public record RevocationInfo(URI ocspResponderUri, Map<String, Object> ocspResponseAttributes) {

    public static final String KEY_OCSP_RESPONSE = "OCSP_RESPONSE";
    public static final String KEY_OCSP_ERROR = "OCSP_ERROR";

}