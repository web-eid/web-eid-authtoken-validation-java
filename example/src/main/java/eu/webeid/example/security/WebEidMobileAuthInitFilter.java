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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import eu.webeid.example.config.WebEidMobileProperties;
import eu.webeid.security.challenge.ChallengeNonceGenerator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class WebEidMobileAuthInitFilter extends OncePerRequestFilter {
    private static final String WEB_EID_MOBILE_AUTH_PATH = "auth";
    private static final ObjectWriter OBJECT_WRITER = new ObjectMapper().writer();
    private final RequestMatcher requestMatcher;
    private final ChallengeNonceGenerator nonceGenerator;
    private final String mobileLoginPath;
    private final WebEidMobileProperties webEidMobileProperties;

    public WebEidMobileAuthInitFilter(String path, String mobileLoginPath, ChallengeNonceGenerator nonceGenerator, WebEidMobileProperties webEidMobileProperties) {
        this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, path);
        this.nonceGenerator = nonceGenerator;
        this.mobileLoginPath = mobileLoginPath;
        this.webEidMobileProperties = webEidMobileProperties;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain) throws IOException, ServletException {
        if (!requestMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        var challenge = nonceGenerator.generateAndStoreNonce();

        String loginUri = ServletUriComponentsBuilder.fromCurrentContextPath()
            .path(mobileLoginPath).build().toUriString();

        String payloadJson = OBJECT_WRITER.writeValueAsString(
            new AuthPayload(challenge.getBase64EncodedNonce(), loginUri,
                webEidMobileProperties.requestSigningCert() ? Boolean.TRUE : null)
        );
        String encoded = Base64.getEncoder().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String authUri = getAuthUri(encoded);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        OBJECT_WRITER.writeValue(response.getWriter(), new AuthUri(authUri));
    }

    private String getAuthUri(String encodedPayload) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(webEidMobileProperties.baseRequestUri());
        if (webEidMobileProperties.baseRequestUri().startsWith("http")) {
            builder.pathSegment(WEB_EID_MOBILE_AUTH_PATH);
        } else {
            builder.host(WEB_EID_MOBILE_AUTH_PATH);
        }
        return builder.fragment(encodedPayload).toUriString();
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record AuthPayload(
        String challenge,
        String loginUri,
        Boolean getSigningCertificate) {
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    record AuthUri(@JsonProperty("auth_uri") String authUri) {
    }
}
