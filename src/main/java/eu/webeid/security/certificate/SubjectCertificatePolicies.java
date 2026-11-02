// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import javax.security.auth.x500.X500Principal;
import java.util.Map;
import java.util.Set;

public final class SubjectCertificatePolicies {

    private static final String ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX = "1.3.6.1.4.1.10015.1.3";

    public static final ASN1ObjectIdentifier ESTEID_SK_2015_MOBILE_ID_POLICY =
        new ASN1ObjectIdentifier(ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX);
    public static final ASN1ObjectIdentifier ESTEID_SK_2015_MOBILE_ID_POLICY_V1 =
        new ASN1ObjectIdentifier(ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX + ".1");
    public static final ASN1ObjectIdentifier ESTEID_SK_2015_MOBILE_ID_POLICY_V2 =
        new ASN1ObjectIdentifier(ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX + ".2");
    public static final ASN1ObjectIdentifier ESTEID_SK_2015_MOBILE_ID_POLICY_V3 =
        new ASN1ObjectIdentifier(ESTEID_SK_2015_MOBILE_ID_POLICY_PREFIX + ".3");

    /**
     * Production document policies for Estonian ID cards, digital ID cards, residence permit cards and diplomatic
     * identity cards issued under the ESTEID2018 and eID certificate-policy generations, grouped by issuer distinguished name.
     *
     * @see <a href="https://www.id.ee/en/article/certificate-policy-for-identity-card-digital-identity-card-residence-permit-card-and-diplomatic-identity-card-2/">
     *     ID.ee certificate policy index for Estonian identity documents</a>
     * @see <a href="https://www.id.ee/wp-content/uploads/2026/08/cp_esteid_v4.1_17.08.2026_allkirjastatud.pdf">
     *     IDEMIA-generation certificate policy</a>
     * @see <a href="https://www.id.ee/wp-content/uploads/2026/06/eid-cp-v-2.0_04.06.2026_allkirjastatud.pdf">
     *     Thales-generation certificate policy</a>
     * @see <a href="https://repository.eidpki.ee/static/documents/CertificateProfiles-20260520.pdf">
     *     ESTEID2025 certificate profile</a>
     */
    public static final Map<X500Principal, Set<ASN1ObjectIdentifier>> ESTEID_PRODUCTION_DOCUMENT_POLICIES = Map.of(
        new X500Principal(
            "CN=ESTEID2018,2.5.4.97=#0c0e4e545245452d3130373437303133,O=SK ID Solutions AS,C=EE"
        ), Set.of(
            // https://www.id.ee/wp-content/uploads/2026/08/cp_esteid_v4.1_17.08.2026_allkirjastatud.pdf Chapter 1.2. Document Name and Identification
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.1"), // Identity card of Estonian citizens
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.2"), // Identity card of European Union citizens
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.3"), // Digital identity card for Estonian residents
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.4"), // Digital identity card for e-residents
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.5"), // Residence permit card for long-term residents
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.6"), // Residence permit card for temporary residents and NATO SOFA
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.7"), // Residence permit card for family members of European Union citizens
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51455.1.1.1")  // Diplomatic identity card
        ),
        new X500Principal(
            "C=EE,O=Zetes Estonia OÜ,2.5.4.97=#0c0e4e545245452d3137303636303439,CN=ESTEID2025"
        ), Set.of(
            // https://www.id.ee/wp-content/uploads/2026/06/eid-cp-v-2.0_04.06.2026_allkirjastatud.pdf Chapter 1.2. Document Name and Identification
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.1"), // Identity card of Estonian citizens
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.2"), // Identity card of European Union citizens
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.3"), // Residence permit card for long-term residents
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.4"), // Residence permit card for temporary residents and the right of stay in the Republic of Estonia.
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.5"), // Residence permit card for family members of EU and UK citizens and the right of residence of UK citizens
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.6"), // Digital identity card of e-residents
            new ASN1ObjectIdentifier("1.3.6.1.4.1.51455.2.1.1")  // Diplomatic identity card
        )
    );

    private SubjectCertificatePolicies() {
        throw new IllegalStateException("Constants class");
    }
}
