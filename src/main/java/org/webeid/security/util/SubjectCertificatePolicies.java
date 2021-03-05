package org.webeid.security.util;

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

    private SubjectCertificatePolicies() {
        throw new IllegalStateException("Constants class");
    }
}
