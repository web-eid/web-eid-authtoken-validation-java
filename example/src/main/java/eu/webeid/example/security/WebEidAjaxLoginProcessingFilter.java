/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package eu.webeid.example.security;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import eu.webeid.example.security.ajax.AjaxAuthenticationFailureHandler;
import eu.webeid.example.security.ajax.AjaxAuthenticationSuccessHandler;
import eu.webeid.security.authtoken.WebEidAuthToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.io.IOException;

public class WebEidAjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private static final Logger LOG = LoggerFactory.getLogger(WebEidAjaxLoginProcessingFilter.class);
    private static final ObjectReader OBJECT_READER = new ObjectMapper().readerFor(WebEidAuthToken.class);

    public WebEidAjaxLoginProcessingFilter(
        String defaultFilterProcessesUrl,
        AuthenticationManager authenticationManager
    ) {
        super(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, defaultFilterProcessesUrl));
        this.setAuthenticationManager(authenticationManager);
        this.setAuthenticationSuccessHandler(new AjaxAuthenticationSuccessHandler());
        this.setAuthenticationFailureHandler(new AjaxAuthenticationFailureHandler());
        this.setSessionAuthenticationStrategy(new SessionFixationProtectionStrategy());
        this.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException {
        requireJsonContentType(request);
        LOG.info("attemptAuthentication(): Reading request body");
        final WebEidAuthToken webEidAuthToken = parseWebEidAuthToken(request);
        LOG.info("attemptAuthentication(): Creating token");
        final PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(null, webEidAuthToken);
        LOG.info("attemptAuthentication(): Calling authentication manager");
        return getAuthenticationManager().authenticate(token);
    }

    private static void requireJsonContentType(HttpServletRequest request) {
        try {
            MediaType contentType = MediaType.parseMediaType(request.getContentType());
            if (!MediaType.APPLICATION_JSON.equalsTypeAndSubtype(contentType)) {
                LOG.warn("Content type not supported: {}", contentType);
                throw new AuthenticationServiceException("Content type not supported: " + contentType);
            }
        } catch (InvalidMediaTypeException e) {
            LOG.warn("Invalid content type", e);
            throw new AuthenticationServiceException("Invalid content type", e);
        }
    }

    private static WebEidAuthToken parseWebEidAuthToken(HttpServletRequest request) {
        try {
            return OBJECT_READER.readValue(request.getReader());
        } catch (JacksonException e) {
            throw new BadCredentialsException("Unable to parse the Web eID authentication token", e);
        } catch (IOException e) {
            throw new AuthenticationServiceException("I/O error while reading the Web eID authentication token", e);
        }
    }
}
