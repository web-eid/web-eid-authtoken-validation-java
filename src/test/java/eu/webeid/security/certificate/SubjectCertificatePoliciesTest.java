// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

import static eu.webeid.security.certificate.SubjectCertificatePolicies.ESTEID2018_ISSUER;
import static eu.webeid.security.certificate.SubjectCertificatePolicies.ESTEID2025_ISSUER;
import static org.assertj.core.api.Assertions.assertThat;

class SubjectCertificatePoliciesTest {

    @Test
    void esteidProductionDocumentPoliciesContainExpectedPolicies() {
        assertThat(SubjectCertificatePolicies.ESTEID_PRODUCTION_DOCUMENT_POLICIES)
            .containsOnlyKeys(ESTEID2018_ISSUER, ESTEID2025_ISSUER);
        assertThat(SubjectCertificatePolicies.ESTEID_PRODUCTION_DOCUMENT_POLICIES.get(ESTEID2018_ISSUER))
            .containsExactlyInAnyOrder(
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.1"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.2"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.3"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.4"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.5"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.6"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.7"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51455.1.1.1")
            );
        assertThat(SubjectCertificatePolicies.ESTEID_PRODUCTION_DOCUMENT_POLICIES.get(ESTEID2025_ISSUER))
            .containsExactlyInAnyOrder(
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.1"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.2"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.3"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.4"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.5"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.6"),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51455.2.1.1")
            );
    }
}
