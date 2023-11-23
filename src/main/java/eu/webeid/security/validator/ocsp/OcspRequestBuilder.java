/*
 * Copyright (c) 2020-2023 Estonian Information System Authority
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

/*
 * Copyright 2017 The Netty Project
 * Copyright (c) 2020-2023 Estonian Information System Authority
 *
 * The Netty Project and The Web eID Project license this file to you under the
 * Apache License, version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package eu.webeid.security.validator.ocsp;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * This is a simplified version of Bouncy Castle's {@link OCSPReqBuilder}.
 *
 * @see OCSPReqBuilder
 */
public final class OcspRequestBuilder {

    private static final SecureRandom GENERATOR = new SecureRandom();

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
            addNonce(builder);
        }

        return builder.build();
    }

    private void addNonce(OCSPReqBuilder builder) {
        final byte[] nonce = new byte[32];
        GENERATOR.nextBytes(nonce);

        final Extension[] extensions = new Extension[]{
            new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                new DEROctetString(nonce))
        };
        builder.setRequestExtensions(new Extensions(extensions));
    }

}
