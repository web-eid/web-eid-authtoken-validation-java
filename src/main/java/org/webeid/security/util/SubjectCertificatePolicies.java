package org.webeid.security.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public final class SubjectCertificatePolicies {

    public static final ASN1ObjectIdentifier EST_MOBILE_ID_POLICY = new ASN1ObjectIdentifier("1.3.6.1.4.1.10015.1.3");

    private SubjectCertificatePolicies() {
        throw new IllegalStateException("Constants class");
    }
}
