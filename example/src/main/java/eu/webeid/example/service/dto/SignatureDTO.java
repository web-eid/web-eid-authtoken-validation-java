// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.service.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SignatureDTO {

    @JsonProperty("signature")
    private String base64Signature;

    public String getBase64Signature() {
        return base64Signature;
    }

    public void setBase64Signature(String base64Signature) {
        this.base64Signature = base64Signature;
    }
}
