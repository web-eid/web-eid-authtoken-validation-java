// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.security.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.webeid.security.authtoken.WebEidAuthToken;

public record AuthTokenDTO(@JsonProperty("auth-token") WebEidAuthToken token) {
}
