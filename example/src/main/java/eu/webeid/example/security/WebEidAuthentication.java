// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.security;

import eu.webeid.security.certificate.CertificateData;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class WebEidAuthentication extends PreAuthenticatedAuthenticationToken implements Authentication {

    private final String idCode;

    public static Authentication fromCertificate(X509Certificate userCertificate, List<GrantedAuthority> authorities) throws CertificateEncodingException {
        final String principalName = getPrincipalNameFromCertificate(userCertificate);
        final String idCode = CertificateData.getSubjectIdCode(userCertificate)
                .orElseThrow(() -> new CertificateEncodingException("Certificate does not contain subject ID code"));
        return new WebEidAuthentication(principalName, idCode, authorities);
    }

    public String getIdCode() {
        return idCode;
    }

    private WebEidAuthentication(String principalName, String idCode, List<GrantedAuthority> authorities) {
        super(principalName, idCode, authorities);
        this.idCode = idCode;
    }

    private static String getPrincipalNameFromCertificate(X509Certificate userCertificate) throws CertificateEncodingException {
        final Optional<String> givenName = CertificateData.getSubjectGivenName(userCertificate);
        final Optional<String> surname = CertificateData.getSubjectSurname(userCertificate);

        if (givenName.isPresent() && surname.isPresent()) {
            return givenName.get() + ' ' + surname.get();
        } else {
            // Organization certificates do not have given name and surname fields.
            return CertificateData.getSubjectCN(userCertificate)
                    .orElseThrow(() -> new CertificateEncodingException("Certificate does not contain subject CN"));
        }
    }

    @Override
    public boolean equals(Object o) {
        if (!super.equals(o)) return false;
        WebEidAuthentication that = (WebEidAuthentication) o;
        return Objects.equals(idCode, that.idCode);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), idCode);
    }
}
