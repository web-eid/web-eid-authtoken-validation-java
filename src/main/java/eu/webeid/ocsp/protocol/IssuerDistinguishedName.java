package eu.webeid.ocsp.protocol;

import org.bouncycastle.asn1.x500.X500Name;

import java.security.cert.X509Certificate;
import java.util.Objects;

public class IssuerDistinguishedName {

    public static X500Name getIssuerDistinguishedName(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        return X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded());
    }

    private IssuerDistinguishedName() {
        throw new IllegalStateException("Utility class");
    }
}
