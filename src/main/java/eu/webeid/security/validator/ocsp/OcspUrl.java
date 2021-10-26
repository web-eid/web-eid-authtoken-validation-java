/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

package eu.webeid.security.validator.ocsp;

import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Objects;

public final class OcspUrl {

    public static final URI AIA_ESTEID_2015 = URI.create("http://aia.sk.ee/esteid2015");

    /**
     * Returns the OCSP responder {@link URI} or {@code null} if it doesn't have one.
     */
    public static URI getOcspUri(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        final X509CertificateHolder certificateHolder;
        try {
            certificateHolder = new X509CertificateHolder(certificate.getEncoded());
            final AuthorityInformationAccess authorityInformationAccess =
                AuthorityInformationAccess.fromExtensions(certificateHolder.getExtensions());
            for (AccessDescription accessDescription :
                authorityInformationAccess.getAccessDescriptions()) {
                if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp) &&
                    accessDescription.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {
                    final String accessLocationUrl = ((ASN1String) accessDescription.getAccessLocation().getName())
                        .getString();
                    return URI.create(accessLocationUrl);
                }
            }
        } catch (IOException | CertificateEncodingException | IllegalArgumentException | NullPointerException e) {
            return null;
        }
        return null;
    }

    private OcspUrl() {
        throw new IllegalStateException("Utility class");
    }
}
