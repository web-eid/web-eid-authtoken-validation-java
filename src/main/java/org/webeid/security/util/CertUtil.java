/*
 * Copyright (c) 2020 The Web eID Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package org.webeid.security.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.stream.Collectors;

public final class CertUtil {

    public static String getSubjectCN(X509Certificate certificate) throws CertificateEncodingException {
        return getField(certificate, BCStyle.CN);
    }

    public static String getSubjectSurname(X509Certificate certificate) throws CertificateEncodingException {
        return getField(certificate, BCStyle.SURNAME);
    }

    public static String getSubjectGivenName(X509Certificate certificate) throws CertificateEncodingException {
        return getField(certificate, BCStyle.GIVENNAME);
    }

    public static String getSubjectIdCode(X509Certificate certificate) throws CertificateEncodingException {
        return getField(certificate, BCStyle.SERIALNUMBER);
    }

    public static String getSubjectCountryCode(X509Certificate certificate) throws CertificateEncodingException {
        return getField(certificate, BCStyle.C);
    }

    private static String getField(X509Certificate certificate, ASN1ObjectIdentifier fieldId) throws CertificateEncodingException {
        final X500Name x500Name = new JcaX509CertificateHolder(certificate).getSubject();
        // Example value: [C=EE, CN=JÕEORG\,JAAK-KRISTJAN\,38001085718, 2.5.4.4=#0c074ac395454f5247, 2.5.4.42=#0c0d4a41414b2d4b524953544a414e, 2.5.4.5=#1311504e4f45452d3338303031303835373138]
        final RDN[] rdns = x500Name.getRDNs(fieldId);
        return Arrays.stream(rdns)
            .map(rdn -> IETFUtils.valueToString(rdn.getFirst().getValue()))
            .collect(Collectors.joining(", "));
    }

}
