// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

class OcspNonceExtensionTest {

    @Test
    void whenNonceExtensionIsCreated_thenItIsEncodedAsNonCriticalOcspNonceExtension() throws Exception {
        final byte[] nonce = HexFormat.of().parseHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        final OcspNonceExtension extension = new OcspNonceExtension(
                Extension.create(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce))
        );
        final ByteArrayOutputStream encodedExtension = new ByteArrayOutputStream();

        extension.encode(encodedExtension);

        assertThat(extension.getId()).isEqualTo("1.3.6.1.5.5.7.48.1.2");
        assertThat(extension.isCritical()).isFalse();
        assertThat(extension.getValue()).containsExactly(
                HexFormat.of().parseHex(
                        "0420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                )
        );
        assertThat(encodedExtension.toByteArray()).containsExactly(
                HexFormat.of().parseHex(
                        "302f06092b060105050730010204220420" +
                                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                )
        );
    }

    @Test
    void whenValueIsReturned_thenItCannotBeUsedToModifyExtension() {
        final OcspNonceExtension extension = OcspNonceExtension.create();
        final byte[] originalValue = extension.getValue();

        final byte[] value = extension.getValue();
        value[2] ^= 1;

        assertThat(extension.getValue()).containsExactly(originalValue);
    }
}
