// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SubjectCertificatePoliciesTest {

    @Test
    void esteidIdCardPoliciesContainOnlyProductionIdCardPolicies() {
        assertThat(SubjectCertificatePolicies.ESTEID_ID_CARD_POLICIES).containsExactlyInAnyOrder(
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.1"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.2"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.1"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.2")
        );
    }
}
