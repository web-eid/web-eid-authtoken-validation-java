// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.testutil;

import java.io.IOException;

public final class OcspResponses {

    private static final int OCSP_RESPONSE_SIGNATURE_OFFSET = 349;

    private OcspResponses() {
    }

    // Corrupts a byte in the signature of ocsp_response.der, so that the response signature is invalid.
    public static byte[] buildOcspResponseBodyWithInvalidSignature() throws IOException {
        final byte[] ocspResponseBytes = ResourceUtil.bytesFromResource("ocsp_response.der");
        ocspResponseBytes[OCSP_RESPONSE_SIGNATURE_OFFSET + 5] = 0x01;
        return ocspResponseBytes;
    }
}
