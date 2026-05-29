// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.security.ajax;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

public class AjaxAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AjaxAuthenticationFailureHandler.class);

    public static final String AUTHENTICATION_FAILED = "Authentication failed: ";

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        final String message = AUTHENTICATION_FAILED + exception.getMessage();
        LOG.warn("onAuthenticationFailure(): exception {}, returning {} {}",
                exception,
                HttpServletResponse.SC_UNAUTHORIZED,
                message);
        final HttpSession session = request.getSession(false);
        if (session != null) {
            LOG.info("Invalidating session");
            session.invalidate();
        }
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
    }
}
