package eu.webeid.security.validator;

import eu.webeid.security.validator.revocationcheck.RevocationInfo;

import java.security.cert.X509Certificate;
import java.util.List;

import static java.util.Objects.requireNonNull;

public record ValidationInfo(X509Certificate subjectCertificate, List<RevocationInfo> revocationInfoList) {

    public ValidationInfo(X509Certificate subjectCertificate, List<RevocationInfo> revocationInfoList) {
        this.subjectCertificate = requireNonNull(subjectCertificate, "subjectCertificate");
        this.revocationInfoList = List.copyOf(requireNonNull(revocationInfoList, "revocationInfoList"));
    }
}
