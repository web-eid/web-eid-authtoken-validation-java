// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;

import static org.assertj.core.api.Assertions.assertThat;

class SubjectCertificatePoliciesTest {

    private static final X500Principal ESTEID2018_ISSUER = new X500Principal(
        "CN=ESTEID2018,2.5.4.97=#0c0e4e545245452d3130373437303133,O=SK ID Solutions AS,C=EE"
    );
    private static final X500Principal ESTEID2025_ISSUER = new X500Principal(
        "C=EE,O=Zetes Estonia OÜ,2.5.4.97=#0c0e4e545245452d3137303636303439,CN=ESTEID2025"
    );

    @Test
    void esteidIdCardPoliciesContainOnlyProductionIdCardPolicies() {
        assertThat(SubjectCertificatePolicies.ESTEID_ID_CARD_POLICIES)
            .containsOnlyKeys(ESTEID2018_ISSUER, ESTEID2025_ISSUER);
        assertThat(SubjectCertificatePolicies.ESTEID_ID_CARD_POLICIES.get(ESTEID2018_ISSUER))
            .containsExactlyInAnyOrder(
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.1"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.2")
        );
        assertThat(SubjectCertificatePolicies.ESTEID_ID_CARD_POLICIES.get(ESTEID2025_ISSUER))
            .containsExactlyInAnyOrder(
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.1"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.2")
        );
    }
}
