// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.security.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.webeid.security.authtoken.WebEidAuthToken;

public class AuthTokenDTO {
    @JsonProperty("auth-token")
    private WebEidAuthToken token;

    public WebEidAuthToken getToken() {
        return token;
    }

    public void setToken(WebEidAuthToken token) {
        this.token = token;
    }
}
