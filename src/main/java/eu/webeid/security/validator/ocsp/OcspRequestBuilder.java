// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.ocsp;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * This is a wrapper around Bouncy Castle's {@link OCSPReqBuilder} that
 * adds the OCSP nonce extension to the request if needed.
 */
public final class OcspRequestBuilder {

    private static final SecureRandom RANDOM_GENERATOR = new SecureRandom();

    private boolean ocspNonceEnabled = true;
    private CertificateID certificateId;

    public OcspRequestBuilder withCertificateId(CertificateID certificateId) {
        this.certificateId = certificateId;
        return this;
    }

    public OcspRequestBuilder enableOcspNonce(boolean ocspNonceEnabled) {
        this.ocspNonceEnabled = ocspNonceEnabled;
        return this;
    }

    /**
     * The returned {@link OCSPReq} is not re-usable/cacheable. It contains a one-time nonce
     * and responders will reject subsequent requests that have the same nonce value.
     */
    public OCSPReq build() throws OCSPException {
        final OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(Objects.requireNonNull(certificateId, "certificateId"));

        if (ocspNonceEnabled) {
            try {
                addNonce(builder);
            } catch (IOException e) {
                throw new OCSPException("Failed to generate OCSP nonce extension", e);
            }
        }

        return builder.build();
    }

    private void addNonce(OCSPReqBuilder builder) throws IOException {
        final byte[] nonce = new byte[32];
        RANDOM_GENERATOR.nextBytes(nonce);

        final Extension[] extensions = new Extension[]{
            new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                // Follow OpenSSL OCSP nonce encoding convention and add double octet string header.
                new DEROctetString(new DEROctetString(nonce)))
        };
        builder.setRequestExtensions(new Extensions(extensions));
    }

}
