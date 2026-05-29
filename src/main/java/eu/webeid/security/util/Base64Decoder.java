// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.util;

import java.util.Base64;

public final class Base64Decoder {

    public static byte[] decodeBase64(String base64Str) throws IllegalArgumentException {
        return Base64.getDecoder().decode(base64Str);
    }

    private Base64Decoder() {
        throw new IllegalStateException("Utility class");
    }
}
