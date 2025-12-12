// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import eu.webeid.example.security.dto.AuthTokenDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;

import java.io.BufferedReader;
import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class WebEidAjaxLoginProcessingFilterTest {

    private static final String AUTH_TOKEN = """
            {"auth-token": {
                "format": "web-eid:1.0",
                "algorithm": "ES384",
                "unverifiedCertificate": "test-certificate",
                "signature": "test-signature"
            }}
            """;

    @Test
    void testAttemptAuthentication() throws Exception {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getMethod()).thenReturn(HttpMethod.POST.name());
        when(request.getHeader("Content-type")).thenReturn("application/json");
        when(request.getReader()).thenReturn(new BufferedReader(new StringReader(AUTH_TOKEN)));

        final AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

        assertDoesNotThrow(() ->
                new WebEidAjaxLoginProcessingFilter("/auth/login", authenticationManager)
                        .attemptAuthentication(request, response));

        final ArgumentCaptor<Authentication> authentication = ArgumentCaptor.forClass(Authentication.class);
        verify(authenticationManager).authenticate(authentication.capture());
        assertThat(authentication.getValue().getCredentials()).isInstanceOfSatisfying(AuthTokenDTO.class, dto -> {
            assertThat(dto.token().format()).isEqualTo("web-eid:1.0");
            assertThat(dto.token().unverifiedCertificate()).isEqualTo("test-certificate");
            assertThat(dto.token().signature()).isEqualTo("test-signature");
        });
    }

    @Test
    void whenJsonIsMalformed_thenPreservesCauseInAuthenticationFailure() throws Exception {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn(HttpMethod.POST.name());
        when(request.getHeader("Content-type")).thenReturn("application/json");
        when(request.getReader()).thenReturn(new BufferedReader(new StringReader("{")));
        final AuthenticationManager manager = mock(AuthenticationManager.class);

        assertThatThrownBy(() -> new WebEidAjaxLoginProcessingFilter("/auth/login", manager)
                .attemptAuthentication(request, mock(HttpServletResponse.class)))
                .isInstanceOf(AuthenticationServiceException.class)
                .hasCauseInstanceOf(JsonProcessingException.class);
        verifyNoInteractions(manager);
    }
}
