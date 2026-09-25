// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.protocol;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;

import java.io.IOException;
import java.util.Objects;

/**
 * This is a wrapper around Bouncy Castle's {@link OCSPReqBuilder} that
 * adds the OCSP nonce extension to the request if needed.
 */
public final class OcspRequestBuilder {

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
     * Builds a request with a fresh nonce when nonce support is enabled.
     * Create a new request for each check so a matching response nonce can establish freshness.
     */
    public OCSPReq build() throws OCSPException {
        final OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(Objects.requireNonNull(certificateId, "certificateId"));

        if (ocspNonceEnabled) {
            try {
                builder.setRequestExtensions(new Extensions(OcspNonceFactory.create()));
            } catch (IOException e) {
                throw new OCSPException("Failed to generate OCSP nonce extension", e);
            }
        }

        return builder.build();
    }

}
