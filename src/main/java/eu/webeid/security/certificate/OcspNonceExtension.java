// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.security.cert.Extension;

import static java.util.Objects.requireNonNull;

/**
 * Encodes a 32-byte OCSP nonce as a JDK certificate extension.
 */
public final class OcspNonceExtension implements Extension {

    private static final int NONCE_LENGTH_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final org.bouncycastle.asn1.x509.Extension extension;

    OcspNonceExtension() {
        try {
            extension = create();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create OCSP nonce extension", e);
        }
    }

    /**
     * Creates an OCSP nonce extension with a fresh, cryptographically random 32-byte nonce.
     * The extension's critical flag is false, as recommended for OCSP requests.
     */
    public static org.bouncycastle.asn1.x509.Extension create() throws IOException {
        final byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        RANDOM.nextBytes(nonce);
        return org.bouncycastle.asn1.x509.Extension.create(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce));
    }

    @Override
    public String getId() {
        return extension.getExtnId().getId();
    }

    @Override
    public boolean isCritical() {
        return extension.isCritical();
    }

    @Override
    public byte[] getValue() {
        // The JDK expects the contents of extnValue, including the inner nonce OCTET STRING.
        return extension.getExtnValue().getOctets().clone();
    }

    @Override
    public void encode(OutputStream outputStream) throws IOException {
        requireNonNull(outputStream, "outputStream").write(extension.getEncoded(ASN1Encoding.DER));
    }
}
