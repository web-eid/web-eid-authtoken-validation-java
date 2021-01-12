/*
 * Copyright (c) 2020 The Web eID Project
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
 * Copyright 2020 The Web eID project
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

package org.webeid.security.validator.ocsp;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.DigestCalculator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * This is a simplified version of Bouncy Castle's {@link OCSPReqBuilder}.
 *
 * @see OCSPReqBuilder
 */
public final class OcspRequestBuilder {

    private static final SecureRandom GENERATOR = new SecureRandom();

    private SecureRandom randomGenerator = GENERATOR;
    private DigestCalculator digestCalculator = Digester.sha1();
    private X509Certificate subjectCertificate;
    private X509Certificate issuerCertificate;

    public OcspRequestBuilder generator(SecureRandom generator) {
        this.randomGenerator = generator;
        return this;
    }

    public OcspRequestBuilder calculator(DigestCalculator calculator) {
        this.digestCalculator = calculator;
        return this;
    }

    public OcspRequestBuilder certificate(X509Certificate certificate) {
        this.subjectCertificate = certificate;
        return this;
    }

    public OcspRequestBuilder issuer(X509Certificate issuer) {
        this.issuerCertificate = issuer;
        return this;
    }

    /**
     * ATTENTION: The returned {@link OCSPReq} is not re-usable/cacheable! It contains a one-time nonce
     * and CA's will (should) reject subsequent requests that have the same nonce value.
     */
    public OCSPReq build() throws OCSPException, IOException, CertificateEncodingException {
        final SecureRandom generator = Objects.requireNonNull(this.randomGenerator, "randomGenerator");
        final DigestCalculator calculator = Objects.requireNonNull(this.digestCalculator, "digestCalculator");
        final X509Certificate certificate = Objects.requireNonNull(this.subjectCertificate, "subjectCertificate");
        final X509Certificate issuer = Objects.requireNonNull(this.issuerCertificate, "issuerCertificate");

        final BigInteger serial = certificate.getSerialNumber();

        final CertificateID certId = new CertificateID(calculator,
            new X509CertificateHolder(issuer.getEncoded()), serial);

        final OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certId);

        final byte[] nonce = new byte[8];
        generator.nextBytes(nonce);

        final Extension[] extensions = new Extension[]{
            new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                new DEROctetString(nonce))
        };

        builder.setRequestExtensions(new Extensions(extensions));

        return builder.build();
    }
}
