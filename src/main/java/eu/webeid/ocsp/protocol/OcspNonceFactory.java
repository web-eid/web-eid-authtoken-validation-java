// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.protocol;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;

import java.io.IOException;
import java.security.SecureRandom;

/**
 * Creates OCSP nonce extensions with fresh 32-byte nonces.
 * The extension's critical flag is false, as recommended for OCSP requests.
 */
public final class OcspNonceFactory {

    private static final int NONCE_LENGTH_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private OcspNonceFactory() {
    }

    public static Extension create() throws IOException {
        final byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        RANDOM.nextBytes(nonce);
        // The nonce is an OCTET STRING inside the extension's extnValue OCTET STRING.
        return Extension.create(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce));
    }
}
