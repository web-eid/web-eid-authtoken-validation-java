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

package eu.webeid.example.security.ui;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.thymeleaf.ITemplateEngine;
import org.thymeleaf.context.Context;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class WebEidLoginPageGeneratingFilter extends OncePerRequestFilter {

    private final RequestMatcher requestMatcher;
    private final String loginProcessingPath;
    private final ITemplateEngine templateEngine;

    public WebEidLoginPageGeneratingFilter(
        String path,
        String loginProcessingPath,
        ITemplateEngine templateEngine
    ) {
        this.requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, path);
        this.loginProcessingPath = loginProcessingPath;
        this.templateEngine = templateEngine;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain chain)
        throws IOException, ServletException {
        if (!requestMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        var csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrf == null) {
            csrf = (CsrfToken) request.getAttribute("_csrf");
        }

        String html = renderTemplate(csrf);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.TEXT_HTML_VALUE);
        response.getWriter().write(html);
    }

    private String renderTemplate(CsrfToken csrf) {
        var ctx = new Context();
        ctx.setVariable("loginProcessingPath", loginProcessingPath);
        ctx.setVariable("csrfHeaderName", csrf != null ? csrf.getHeaderName() : "X-CSRF-TOKEN");
        ctx.setVariable("csrfToken", csrf != null ? csrf.getToken() : "");
        return templateEngine.process("webeid-login", ctx);
    }
}
