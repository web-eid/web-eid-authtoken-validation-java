// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

public class CertificateDTO {

    private String certificate;
    private List<SignatureAlgorithmDTO> supportedSignatureAlgorithms;

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public List<SignatureAlgorithmDTO> getSupportedSignatureAlgorithms() {
        return supportedSignatureAlgorithms;
    }

    public void setSupportedSignatureAlgorithms(List<SignatureAlgorithmDTO> supportedSignatureAlgorithms) {
        this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
    }

    public X509Certificate toX509Certificate() throws CertificateException {
        byte[] certificateBytes = Base64.getDecoder().decode(certificate);
        InputStream inStream = new ByteArrayInputStream(certificateBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(inStream);
    }

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    public List<String> getSupportedHashFunctionNames() {
        return supportedSignatureAlgorithms == null ? List.of() : supportedSignatureAlgorithms
                .stream()
                .map(SignatureAlgorithmDTO::getHashFunction)
                .distinct()
                .toList();
    }
}
