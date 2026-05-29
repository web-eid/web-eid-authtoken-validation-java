// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.security.ajax;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Write custom response on having user successfully authenticated.
 * <p>
 * This is not required in production application, but to demonstrate that
 * authentication and authorization steps have been passed.
 */
@Component
public class AjaxAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AjaxAuthenticationSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    )
            throws IOException {
        LOG.info("onAuthenticationSuccess(): {}", authentication);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader("Content-Type", "application/json; charset=utf-8");

        response.getWriter().write(AuthSuccessDTO.asJson(authentication));
    }

    public static class AuthSuccessDTO {
        private static final ObjectWriter OBJECT_WRITER = new ObjectMapper().writerFor(AuthSuccessDTO.class);

        @JsonProperty("sub")
        private String sub;

        @JsonProperty("auth")
        private String auth;

        public static String asJson(Authentication authentication) throws JsonProcessingException {
            final AuthSuccessDTO dto = new AuthSuccessDTO();
            dto.sub = authentication.getName();
            dto.auth = authentication.getAuthorities().toString();
            return OBJECT_WRITER.writeValueAsString(dto);
        }
    }
}
