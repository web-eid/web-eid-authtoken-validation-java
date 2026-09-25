// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import eu.webeid.ocsp.protocol.OcspNonceFactory;
import org.bouncycastle.asn1.ASN1Encoding;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.cert.Extension;

import static java.util.Objects.requireNonNull;

/**
 * Adapts an OCSP nonce extension to the JDK certificate extension API.
 */
final class OcspNonceExtension implements Extension {

    private final org.bouncycastle.asn1.x509.Extension extension;

    static OcspNonceExtension create() {
        try {
            return new OcspNonceExtension(OcspNonceFactory.create());
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to generate OCSP nonce extension", e);
        }
    }

    OcspNonceExtension(org.bouncycastle.asn1.x509.Extension extension) {
        this.extension = requireNonNull(extension, "extension");
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
