// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;

public final class CertificateData {

    public static Optional<String> getSubjectCN(X509Certificate certificate) throws CertificateEncodingException {
        return getSubjectField(certificate, BCStyle.CN);
    }

    public static Optional<String> getSubjectSurname(X509Certificate certificate) throws CertificateEncodingException {
        return getSubjectField(certificate, BCStyle.SURNAME);
    }

    public static Optional<String> getSubjectGivenName(X509Certificate certificate) throws CertificateEncodingException {
        return getSubjectField(certificate, BCStyle.GIVENNAME);
    }

    public static Optional<String> getSubjectIdCode(X509Certificate certificate) throws CertificateEncodingException {
        return getSubjectField(certificate, BCStyle.SERIALNUMBER);
    }

    public static Optional<String> getSubjectCountryCode(X509Certificate certificate) throws CertificateEncodingException {
        return getSubjectField(certificate, BCStyle.C);
    }

    private static Optional<String> getSubjectField(X509Certificate certificate, ASN1ObjectIdentifier fieldId) throws CertificateEncodingException {
        return getField(new JcaX509CertificateHolder(certificate).getSubject(), fieldId);
    }

    private static Optional<String> getField(X500Name x500Name, ASN1ObjectIdentifier fieldId) {
        // Example value: [C=EE, CN=JÕEORG\,JAAK-KRISTJAN\,38001085718, 2.5.4.4=#0c074ac395454f5247, 2.5.4.42=#0c0d4a41414b2d4b524953544a414e, 2.5.4.5=#1311504e4f45452d3338303031303835373138]
        final RDN[] rdns = x500Name.getRDNs(fieldId);
        if (rdns.length == 0 || rdns[0].getFirst() == null) {
            return Optional.empty();
        }
        return Optional.of(Arrays.stream(rdns)
            .map(rdn -> IETFUtils.valueToString(rdn.getFirst().getValue()))
            .collect(Collectors.joining(", ")));
    }

    private CertificateData() {
        throw new IllegalStateException("Utility class");
    }

}
