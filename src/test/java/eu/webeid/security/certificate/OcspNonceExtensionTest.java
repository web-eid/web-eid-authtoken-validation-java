// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

class OcspNonceExtensionTest {

    @Test
    void whenExtensionsAreCreated_thenNoncesAreFreshAnd32BytesLong() throws Exception {
        final byte[] firstNonce = ASN1OctetString.getInstance(OcspNonceExtension.create().getParsedValue()).getOctets();
        final byte[] secondNonce = ASN1OctetString.getInstance(OcspNonceExtension.create().getParsedValue()).getOctets();

        assertThat(firstNonce).hasSize(32);
        assertThat(secondNonce).hasSize(32).isNotEqualTo(firstNonce);
    }

    @Test
    void whenBcExtensionIsCreated_thenItEncodesANonCritical32ByteNonce() throws Exception {
        final Extension extension = Extension.getInstance(OcspNonceExtension.create().getEncoded());

        assertThat(extension.getExtnId().getId()).isEqualTo("1.3.6.1.5.5.7.48.1.2");
        assertThat(extension.isCritical()).isFalse();
        assertThat(ASN1OctetString.getInstance(extension.getParsedValue()).getOctets()).hasSize(32);
    }

    @Test
    void whenNonceExtensionIsCreated_thenItIsEncodedAsNonCriticalOcspNonceExtension() throws Exception {
        final OcspNonceExtension extension = new OcspNonceExtension();
        final ByteArrayOutputStream encodedExtension = new ByteArrayOutputStream();

        extension.encode(encodedExtension);

        assertThat(extension.getId()).isEqualTo("1.3.6.1.5.5.7.48.1.2");
        assertThat(extension.isCritical()).isFalse();
        assertThat(extension.getValue()).hasSize(34).startsWith((byte) 0x04, (byte) 0x20);
        assertThat(encodedExtension.toByteArray()).containsExactly(
                HexFormat.of().parseHex(
                        "302f06092b06010505073001020422" + HexFormat.of().formatHex(extension.getValue())
                )
        );
    }

    @Test
    void whenValueIsReturned_thenItCannotBeUsedToModifyExtension() {
        final OcspNonceExtension extension = new OcspNonceExtension();
        final byte[] originalValue = extension.getValue();

        final byte[] value = extension.getValue();
        value[2] ^= 1;

        assertThat(extension.getValue()).containsExactly(originalValue);
    }
}
