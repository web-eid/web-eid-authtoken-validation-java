// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
import java.util.Optional;

public final class OcspUrl {

    /**
     * Returns the OCSP responder {@link URI} or an empty {@code Optional} if it doesn't have one.
     */
    public static Optional<URI> getOcspUri(X509Certificate certificate) {
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
                    return Optional.of(URI.create(accessLocationUrl));
                }
            }
        } catch (IOException | CertificateEncodingException | IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    private OcspUrl() {
        throw new IllegalStateException("Utility class");
    }
}
