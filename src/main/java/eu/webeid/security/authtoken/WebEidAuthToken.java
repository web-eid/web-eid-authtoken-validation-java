// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.authtoken;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class WebEidAuthToken {

    private String unverifiedCertificate;
    private String signature;
    private String algorithm;
    private String format;

    public String getUnverifiedCertificate() {
        return unverifiedCertificate;
    }

    public void setUnverifiedCertificate(String unverifiedCertificate) {
        this.unverifiedCertificate = unverifiedCertificate;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

}
