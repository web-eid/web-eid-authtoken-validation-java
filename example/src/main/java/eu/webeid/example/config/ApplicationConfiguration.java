// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.example.config;

import eu.webeid.example.security.AuthTokenDTOAuthenticationProvider;
import eu.webeid.example.security.WebEidAjaxLoginProcessingFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
public class ApplicationConfiguration implements WebMvcConfigurer {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthTokenDTOAuthenticationProvider authTokenDTOAuthenticationProvider, AuthenticationConfiguration authConfig) throws Exception {
        return http
                .authenticationProvider(authTokenDTOAuthenticationProvider)
                .addFilterBefore(new WebEidAjaxLoginProcessingFilter("/auth/login", authConfig.getAuthenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()))
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .build();
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("index");
        registry.addViewController("/welcome").setViewName("welcome");
    }

}
