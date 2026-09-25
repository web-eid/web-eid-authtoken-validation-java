// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.ocsp.protocol;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OcspNonceFactoryTest {

    @Test
    void whenNonceExtensionIsCreated_thenItEncodesANonCritical32ByteNonce() throws Exception {
        final Extension decodedExtension = Extension.getInstance(OcspNonceFactory.create().getEncoded());

        assertThat(decodedExtension.getExtnId().getId()).isEqualTo("1.3.6.1.5.5.7.48.1.2");
        assertThat(decodedExtension.isCritical()).isFalse();
        assertThat(ASN1OctetString.getInstance(decodedExtension.getParsedValue()).getOctets()).hasSize(32);
    }

    @Test
    void whenExtensionsAreCreated_thenNoncesAreFreshAnd32BytesLong() throws Exception {
        final byte[] firstNonce = ASN1OctetString.getInstance(
                OcspNonceFactory.create().getParsedValue()).getOctets();
        final byte[] secondNonce = ASN1OctetString.getInstance(
                OcspNonceFactory.create().getParsedValue()).getOctets();

        assertThat(firstNonce).hasSize(32);
        assertThat(secondNonce).hasSize(32).isNotEqualTo(firstNonce);
    }
}
