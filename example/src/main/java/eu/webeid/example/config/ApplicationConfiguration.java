// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.config;

import eu.webeid.example.security.AuthTokenDTOAuthenticationProvider;
import eu.webeid.example.security.WebEidAjaxLoginProcessingFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.function.Supplier;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class ApplicationConfiguration implements WebMvcConfigurer {

    @Bean
    public SecurityFilterChain filterChain(
        HttpSecurity http,
        AuthTokenDTOAuthenticationProvider authTokenDTOAuthenticationProvider,
        AuthenticationConfiguration authConfig,
        YAMLConfig config,
        @Value("${web-eid-auth-token.csrf.use-spa-configuration:false}") boolean useSpaCsrfConfiguration,
        @Value("${web-eid-auth-token.validation.local-origin}") String localOrigin
    ) throws Exception {
        if (useSpaCsrfConfiguration) {
            http
                .csrf(csrf -> csrf
                    .csrfTokenRepository(createDefaultCsrfTokenRepository(localOrigin))
                    .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()))
                .cors(Customizer.withDefaults());
        }
        return http
                .authenticationProvider(authTokenDTOAuthenticationProvider)
                .addFilterBefore(new WebEidAjaxLoginProcessingFilter("/auth/login", authConfig.getAuthenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()))
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .build();
    }

    @ConditionalOnProperty(name = "web-eid-auth-token.csrf.use-spa-configuration", havingValue = "true")
    @Bean
    public WebMvcConfigurer corsConfigurer(YAMLConfig config) {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                    .allowedOrigins(config.getCorsAllowedOrigin())
                    .allowCredentials(true);
            }
        };
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("index");
        registry.addViewController("/welcome").setViewName("welcome");
    }

    private CookieCsrfTokenRepository createDefaultCsrfTokenRepository(String localOrigin) {
        CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        cookieCsrfTokenRepository.setCookieCustomizer(cookie -> cookie
            .domain(toApexDomain(localOrigin))
            .sameSite("Lax")
        );
        return cookieCsrfTokenRepository;
    }

    private String toApexDomain(String localOrigin) {
        if (StringUtils.isBlank(localOrigin)) {
            return null;
        }

        String hostname = StringUtils.substringAfter(localOrigin, "//");
        String[] labels = hostname.split("\\.");
        if (labels.length <= 2) {
            return hostname;
        }
        return labels[labels.length - 2] + "." + labels[labels.length - 1];
    }

    private static final class SpaCsrfTokenRequestHandler implements CsrfTokenRequestHandler {
        private final CsrfTokenRequestHandler plain = new CsrfTokenRequestAttributeHandler();
        private final CsrfTokenRequestHandler xor = new XorCsrfTokenRequestAttributeHandler();

        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
            xor.handle(request, response, csrfToken);
            csrfToken.get();
        }

        @Override
        public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
            String headerValue = request.getHeader(csrfToken.getHeaderName());
            return (StringUtils.isNotBlank(headerValue) ? plain : xor).resolveCsrfTokenValue(request, csrfToken);
        }
    }

}
