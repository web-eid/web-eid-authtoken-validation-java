// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

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
     * identity cards issued under the ESTEID2018 and eID certificate-policy generations.
     *
     * @see <a href="https://www.id.ee/artikkel/id-kaardi-digi-id-elamisloakaardi-ja-diplomaadikaardi-sertifitseerimispoliitika/">
     *     Estonian identity-document certificate policies</a>
     */
    public static final Set<ASN1ObjectIdentifier> ESTEID_PRODUCTION_DOCUMENT_POLICIES = Set.of(
        // ESTEID2018 / IDEMIA generation
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.1"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.2"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.3"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.4"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.5"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.6"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.1.7"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51455.1.1.1"),
        // eID / Thales generation
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.1"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.2"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.3"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.4"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.5"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.2.1.6"),
        new ASN1ObjectIdentifier("1.3.6.1.4.1.51455.2.1.1")
    );

    private SubjectCertificatePolicies() {
        throw new IllegalStateException("Constants class");
    }
}
