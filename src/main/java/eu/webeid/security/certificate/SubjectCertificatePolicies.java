// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

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
     * Production document policies for Estonian and European Union citizen ID cards issued under the ESTEID2018
     * and eID certificate-policy generations.
     *
     * @see <a href="https://www.id.ee/en/article/certificate-policy-for-identity-card-digital-identity-card-residence-permit-card-and-diplomatic-identity-card-2/">
     *     ID.ee certificate policy index for Estonian identity documents</a>
     * @see <a href="https://www.id.ee/wp-content/uploads/2026/08/cp_esteid_v4.1_17.08.2026_allkirjastatud.pdf">
     *     IDEMIA-generation certificate policy</a>
     * @see <a href="https://www.skidsolutions.eu/resources/certificate-policies/">
     *     SK ID Solutions certificate policies</a>
     * @see <a href="https://www.skidsolutions.eu/resources/profiles/">
     *     SK ID Solutions certificate profiles</a>
     * @see <a href="https://www.skidsolutions.eu/upload/files/SK-CPR-ESTEID2018-EN-v1_3_20220217.pdf">
     *     ESTEID2018 certificate profile</a>
     * @see <a href="https://www.id.ee/wp-content/uploads/2026/06/eid-cp-v-2.0_04.06.2026_allkirjastatud.pdf">
     *     Thales-generation certificate policy</a>
     * @see <a href="https://repository.eidpki.ee/repository/">
     *     Zetes Estonia trust-service repository</a>
     * @see <a href="https://repository.eidpki.ee/static/documents/CertificateProfiles-20260520.pdf">
     *     ESTEID2025 certificate profile</a>
     */
    public static final ASN1ObjectIdentifier[] ESTEID_ID_CARD_POLICIES = {
        // ESTEID2018 / IDEMIA generation
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.1"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.2"),
        // eID / Thales generation
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.1"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.2")
    };

    private SubjectCertificatePolicies() {
        throw new IllegalStateException("Constants class");
    }
}
