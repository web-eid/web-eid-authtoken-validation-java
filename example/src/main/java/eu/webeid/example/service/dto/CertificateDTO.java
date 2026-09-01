// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.service.dto;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

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

    public List<String> getSupportedHashFunctionNames() {
        return supportedSignatureAlgorithms == null ? new ArrayList<>() : supportedSignatureAlgorithms
                .stream()
                .map(SignatureAlgorithmDTO::getHashFunction)
                .distinct()
                .collect(Collectors.toList());
    }
}
