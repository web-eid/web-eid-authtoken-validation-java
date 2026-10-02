/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
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

package eu.webeid.ocsp.protocol;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;

import static eu.webeid.ocsp.protocol.IssuerDistinguishedName.getIssuerDistinguishedName;
import static eu.webeid.security.testutil.Certificates.getMariliisEsteid2015Cert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class IssuerDistinguishedNameTest {

    private static final X500Name ISSUER_DN = new X500Name("CN=TEST of ESTEID-SK 2015, OID.2.5.4.97=NTREE-10747013, O=AS Sertifitseerimiskeskus, C=EE");

    @Test
    void whenCertificateGiven_thenReturnsIssuerDistinguishedName() throws Exception {
        assertThat(getIssuerDistinguishedName(getMariliisEsteid2015Cert())).isEqualTo(ISSUER_DN);
    }

    @Test
    void whenCertificateIsNull_thenThrows() {
        assertThatNullPointerException().isThrownBy(() -> getIssuerDistinguishedName(null));
    }
}
