// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
